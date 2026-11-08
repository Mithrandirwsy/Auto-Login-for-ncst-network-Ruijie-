#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
校园网自动认证工具 —— 锐捷 ePortal (RG-SAM+) 网页认证
适用：华北理工大学 ncst.edu.cn（校园 Wi-Fi 10.x 网段）

原理：
  1. 定期请求联网探测地址，判断当前是否为"未认证"状态；
  2. 未认证时向任意 HTTP 地址发请求，取被 AC 劫持后返回的认证页——
     可能是 302 跳转（从 Location 取），也可能是 200 直接返回认证页 HTML
     （从 meta refresh / JS 跳转 / 隐藏表单字段里取），两种都能处理；
  3. 用页面里带回的 wlanuserip / nasip / wlanacname 组 queryString，
     POST /eportal/InterFace.do?method=login 完成认证（锐捷要求这些参数原样带回，
     自己硬构造会被判为"设备未注册"）；
  4. 认证成功后再次探测确认，失败则按退避策略重试（避免账号被锁）。

仅使用 Python 标准库，无需 pip 安装任何依赖。
密码使用 Windows DPAPI 加密保存，只有当前 Windows 用户能解密。
"""

import argparse
import base64
import ctypes
import json
import logging
import logging.handlers
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

APP_NAME = "CampusNetAutoLogin"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
LOG_DIR = BASE_DIR / "logs"
DEBUG_DIR = BASE_DIR / "debug"

DEFAULT_CONFIG = {
    "_comment": "用户名/密码请运行 setup.bat 或 python autologin.py --setup 设置",
    "username": "",
    "password_dpapi": "",
    "password_plain": "",
    "service": "",
    "ssid_whitelist": ["ncst.edu.cn"],
    "portal_hosts": ["172.30.0.11", "login.ncst.edu.cn"],
    "probe_urls": [
        "http://connect.rom.miui.com/generate_204",
        "http://www.msftconnecttest.com/connecttest.txt",
        "http://www.baidu.com/",
    ],
    "check_interval_seconds": 15,
    "login_retry_seconds": 45,
    "max_fail_per_hour": 4,
    "request_timeout": 6,
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
}

log = logging.getLogger(APP_NAME)


# --------------------------------------------------------------------------
# 日志
# --------------------------------------------------------------------------
def setup_logging(verbose=False):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.DEBUG)
    log.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    fh = logging.handlers.RotatingFileHandler(
        LOG_DIR / "autologin.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.addHandler(fh)

    if sys.stdout and sys.stdout.isatty():
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        ch.setLevel(logging.DEBUG if verbose else logging.INFO)
        log.addHandler(ch)


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception as e:
            log.error("配置文件读取失败，使用默认配置：%s", e)
    return cfg


def save_config(cfg):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# Windows DPAPI 加解密（密码不落盘明文）
# --------------------------------------------------------------------------
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    func = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    func.argtypes = [
        ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DATA_BLOB),
    ]
    func.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    ok = func(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError(f"DPAPI 调用失败 (error={ctypes.get_last_error()})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def protect(text: str) -> str:
    return base64.b64encode(_dpapi(text.encode("utf-8"), True)).decode("ascii")


def unprotect(token: str) -> str:
    return _dpapi(base64.b64decode(token), False).decode("utf-8")


def get_password(cfg):
    if cfg.get("password_dpapi"):
        try:
            return unprotect(cfg["password_dpapi"])
        except Exception as e:
            log.error("密码解密失败（可能换了 Windows 账号）：%s", e)
    return cfg.get("password_plain", "")


# --------------------------------------------------------------------------
# 网络状态
# --------------------------------------------------------------------------
def _fetch(url, timeout=6):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_CONFIG["user_agent"],
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "close",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.geturl(), r.read(8192)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192)
        except Exception:
            body = b""
        return e.code, e.geturl() or url, body


PORTAL_SIGNS = (b"eportal", b"interface.do", b"wlanuserip", b"nasip=", b"wlanacname")


def _looks_like_portal(body: bytes, final_url: str = "") -> bool:
    low = body.lower()
    if any(s in low for s in PORTAL_SIGNS):
        return True
    if "eportal" in final_url.lower():
        return True
    for enc in ("utf-8", "gbk"):
        try:
            text = body.decode(enc, "ignore")
        except Exception:
            continue
        if ("认证" in text and ("登录" in text or "校园网" in text)) or "请先认证" in text:
            return True
    return False


# 认证页里的设备参数名（锐捷要求原样带回去）
PARAM_KEYS = ("wlanuserip", "wlanacname", "nasip", "mac", "t", "url", "vid", "snmpagentip", "mode")

# 最近一次被劫持时抓到的原始页面，供登录阶段复用
_LAST_HIJACK = {"url": "", "body": b""}


def _decode_text(body):
    for enc in ("utf-8", "gbk"):
        try:
            return body.decode(enc)
        except Exception:
            continue
    return body.decode("utf-8", "ignore")


def _hidden_params(body):
    """从认证页的隐藏字段 / JS 变量里取设备参数。

    不少 AC 是"内容劫持"——原地址直接返回认证页 HTML，没有 302，拿不到 Location，
    但页面自己一定带着 wlanuserip / nasip 这些值，否则浏览器也登不上。
    """
    text = _decode_text(body)
    params = {}

    for m in re.finditer(r"<input\b[^>]*>", text, re.I):
        tag = m.group(0)
        n = re.search(r"\bname\s*=\s*[\"']([^\"']+)[\"']", tag, re.I)
        v = re.search(r"\bvalue\s*=\s*[\"']([^\"']*)[\"']", tag, re.I)
        if n and v and n.group(1).lower() in PARAM_KEYS:
            params[n.group(1)] = v.group(1)

    for key in PARAM_KEYS:
        if key in params:
            continue
        # 前面不能紧跟字母数字下划线，否则 content="..." 里的 t= 会被误判
        m = re.search(
            r"(?<![A-Za-z0-9_])" + key + r"\s*[=:]\s*[\"']([^\"']+)[\"']", text, re.I
        )
        if m:
            params[key] = m.group(1)
    return params


def _query_from_params(params):
    if not params.get("wlanuserip"):
        return ""
    parts = []
    for key in ("wlanuserip", "wlanacname", "nasip", "mac", "t", "vid", "snmpagentip", "mode"):
        val = params.get(key)
        if val:
            parts.append(f"{key}={urllib.parse.quote(val, safe='')}")
    parts.append("url=" + urllib.parse.quote(params.get("url") or "http://www.baidu.com/", safe=""))
    return "&".join(parts)


def discover_portal(body, final_url, cfg):
    """从劫持页里找出真正的认证页地址（主机必须在白名单内）。找不到返回 ''。"""
    hosts = [h.lower() for h in (cfg.get("portal_hosts") or [])]
    if not hosts:
        return ""
    base = "http://" + hosts[0]
    # 若劫持响应本身就落在门户主机上（常见于内容劫持），沿用它带端口的 origin
    fp = urllib.parse.urlsplit(final_url or "")
    if (fp.hostname or "").lower() in hosts:
        base = f"{fp.scheme or 'http'}://{fp.netloc}"

    text = _decode_text(body)
    cands = []
    # meta refresh
    for m in re.finditer(
        r"http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*?content\s*=\s*[\"']([^\"']+)[\"']", text, re.I
    ):
        u = re.search(r"url\s*=\s*(.+)$", m.group(1), re.I | re.S)
        if u:
            cands.append(u.group(1))
    # JS 跳转
    for m in re.finditer(
        r"(?:top\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=|\()\s*[\"']([^\"']+)[\"']", text, re.I
    ):
        cands.append(m.group(1))
    # 绝对 URL / 相对路径
    for m in re.finditer(r"https?://[^\s\"'<>\\]+", text, re.I):
        cands.append(m.group(0))
    for m in re.finditer(r"[\"'](/eportal/[^\"']*)[\"']", text, re.I):
        cands.append(m.group(1))

    best = ""
    for raw in cands:
        c = raw.replace("\\/", "/").replace("&amp;", "&").strip().strip("'\"")
        if not c:
            continue
        if c.startswith("/"):
            c = base + c
        elif c.startswith("//"):
            c = "http:" + c
        elif not c.lower().startswith("http"):
            continue

        parts = urllib.parse.urlsplit(c)
        if (parts.hostname or "").lower() not in hosts:
            continue

        path = parts.path or "/eportal/index.jsp"
        if not path.lower().startswith("/eportal"):
            path = "/eportal/index.jsp"
        query = parts.query or _query_from_params(_hidden_params(body))
        cand = urllib.parse.urlunsplit((parts.scheme or "http", parts.netloc, path, query, ""))
        if "wlanuserip=" in query:
            return cand
        if not best:
            best = cand
    if best:
        return best

    # 页面里没有任何门户地址（典型的"门户页直出"，URL 仍是探测地址）：
    # 用白名单主机拼地址，设备参数从页面隐藏字段里取
    query = _query_from_params(_hidden_params(body))
    if query:
        return base + "/eportal/index.jsp?" + query
    return ""


def _save_hijack_snapshot(body, url):
    """把劫持页存一份，万一解析不出来也有据可查。"""
    try:
        DEBUG_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_DIR / "hijack_latest.html").write_text(
            f"<!-- 来源: {url} -->\n" + _decode_text(body), encoding="utf-8"
        )
    except Exception:
        pass


def probe(timeout=6, cfg=None):
    """返回 (state, portal_url, detail)

    state: 'online' | 'offline'
    portal_url: 解析出的认证页完整地址（含 queryString），解析不出则为 None
    """
    cfg = cfg or load_config()
    last = "无法连接任何探测地址"
    for url in cfg.get("probe_urls") or DEFAULT_CONFIG["probe_urls"]:
        try:
            code, final, body = _fetch(url, timeout=timeout)
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
            continue

        if _looks_like_portal(body, final):
            _LAST_HIJACK["url"], _LAST_HIJACK["body"] = final, body
            portal = discover_portal(body, final, cfg)
            if portal:
                return "offline", portal, f"被认证页劫持 (HTTP {code})"
            _save_hijack_snapshot(body, final)
            return "offline", None, f"被认证页劫持但未解析出设备参数，已存 debug/hijack_latest.html"

        if url.endswith("generate_204"):
            if code == 204:
                return "online", None, "generate_204 返回 204"
            last = f"generate_204 返回 {code}"
        elif "connecttest.txt" in url:
            if code == 200 and b"Microsoft Connect Test" in body:
                return "online", None, "connecttest 正常"
            last = f"connecttest 返回 {code} / {len(body)}B"
        else:
            if code == 200 and len(body) > 1000:
                return "online", None, f"{url} 正常返回 {len(body)}B"
            last = f"{url} 返回 {code} / {len(body)}B"
    return "offline", None, last


def local_ip_towards(host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(1)
            s.connect((host, 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return ""


def current_ssid():
    """返回当前 Wi-Fi SSID；有线连接返回 None；未连接返回 ''。"""
    try:
        out = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
    except Exception:
        return None
    text = out.decode("mbcs", "ignore") if os.name == "nt" else out.decode("utf-8", "ignore")
    m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", text, re.M)
    return m.group(1) if m else ""


def ssid_allowed(cfg):
    allowed = cfg.get("ssid_whitelist") or []
    if not allowed:
        return True
    ssid = current_ssid()
    if ssid is None:          # 有线连接，不校验
        return True
    if ssid == "":
        return False
    return ssid in allowed


# --------------------------------------------------------------------------
# 认证
# --------------------------------------------------------------------------
def _dq(s: str) -> str:
    """锐捷前端用的是双重 encodeURIComponent。"""
    return urllib.parse.quote(urllib.parse.quote(s or "", safe=""), safe="")


def origin_of(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def host_allowed(host: str, cfg) -> bool:
    return host.lower() in [h.lower() for h in cfg.get("portal_hosts", [])]


def do_login(cfg, portal_url=None, dry=False):
    """执行一次认证。返回 (ok, message)。"""
    username = cfg.get("username", "").strip()
    password = get_password(cfg)
    if not username or not password:
        return False, "尚未配置账号密码，请先运行 setup.bat"

    # --- 1. 确定认证页地址与设备参数 queryString ---
    portal = ""
    if portal_url:
        host = urllib.parse.urlsplit(portal_url).hostname or ""
        if host_allowed(host, cfg):
            portal = portal_url

    if not portal:
        portal = discover_portal(
            _LAST_HIJACK.get("body") or b"", _LAST_HIJACK.get("url") or "", cfg
        )
    if not portal:
        state, found, detail = probe(cfg.get("request_timeout", 6), cfg)
        if state == "online":
            return True, "当前已在线，无需认证"
        portal = found or ""
        if not portal:
            return False, f"未取到认证页参数（{detail}），本次没有提交账号密码"

    host = urllib.parse.urlsplit(portal).hostname or ""
    if not host_allowed(host, cfg):
        return False, f"认证页域名 {host} 不在白名单内，为安全起见不提交账号密码"

    query = urllib.parse.urlsplit(portal).query
    if "wlanuserip=" not in query:
        q2 = _query_from_params(_hidden_params(_LAST_HIJACK.get("body") or b""))
        if q2:
            query = q2
    if "wlanuserip=" not in query:
        return False, (
            "认证页未提供 wlanuserip 等设备参数（锐捷要求原样带回，硬构造会被判为"
            "\"设备未注册\"）。页面快照已存 debug/hijack_latest.html，请发给开发者。"
        )

    api = origin_of(portal) + "/eportal/InterFace.do?method=login"
    body = "&".join([
        "userId=" + _dq(username),
        "password=" + _dq(password),
        "service=" + _dq(cfg.get("service", "")),
        "queryString=" + _dq(query),
        "operatorPwd=",
        "operatorUserId=",
        "validcode=",
        "passwordEncrypt=" + _dq("false"),
    ])

    if dry:
        log.info("[演练] 将向 %s 提交 userId=%s ...", api, username)
        return True, "演练模式未实际提交"

    log.info("正在认证：账号=%s 认证页=%s", username, origin_of(portal))
    log.debug("queryString=%s", query)
    try:
        req = urllib.request.Request(
            api,
            data=body.encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "User-Agent": cfg.get("user_agent", DEFAULT_CONFIG["user_agent"]),
                "Referer": portal,
                "Connection": "close",
            },
        )
        with urllib.request.urlopen(req, timeout=cfg.get("request_timeout", 6)) as r:
            raw = r.read(8192)
    except Exception as e:
        return False, f"请求认证接口失败：{e}"

    text = raw.decode("utf-8", "replace").strip()
    log.debug("认证接口返回：%s", text[:500])

    try:
        data = json.loads(text)
    except Exception:
        return False, f"认证接口返回非 JSON：{text[:200]}"

    result = str(data.get("result", "")).lower()
    message = (data.get("message") or "").strip()

    if result == "success":
        return True, message or "认证成功"
    if "已经在线" in message or "已在线" in message or "already" in message.lower():
        return True, message
    return False, message or text[:200]


def verify_online(retries=6, delay=2.0):
    for i in range(retries):
        state, _, _ = probe()
        if state == "online":
            return True
        time.sleep(delay)
    return False


# --------------------------------------------------------------------------
# 守护进程
# --------------------------------------------------------------------------
LOCK_PORT = 51789


def acquire_single_instance():
    """用一个本地端口做单实例锁：进程退出时自动释放，不会残留。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", LOCK_PORT))
        s.listen(1)
        return s
    except OSError:
        s.close()
        return None


def run_daemon():
    lock = acquire_single_instance()
    if lock is None:
        log.info("已有守护进程在运行，本次启动退出")
        return 0

    log.info("=" * 60)
    log.info("自动认证守护进程启动（PID %s）", os.getpid())
    fail_times = []
    sleeping_off = False
    warned_no_cred = False

    while True:
        try:
            cfg = load_config()
            interval = int(cfg.get("check_interval_seconds", 15))
            retry = int(cfg.get("login_retry_seconds", 45))
            max_fail = int(cfg.get("max_fail_per_hour", 4))

            if not cfg.get("username") or not get_password(cfg):
                if not warned_no_cred:
                    log.warning("尚未配置账号密码，等待配置（运行 setup.bat）")
                    warned_no_cred = True
                time.sleep(30)
                continue
            warned_no_cred = False

            if not ssid_allowed(cfg):
                if not sleeping_off:
                    log.info("当前不在校园网 Wi-Fi（%s），暂停认证", current_ssid() or "未连接")
                    sleeping_off = True
                time.sleep(30)
                continue
            sleeping_off = False

            state, portal_url, detail = probe(cfg.get("request_timeout", 6))
            if state == "online":
                time.sleep(interval)
                continue

            now = time.time()
            fail_times = [t for t in fail_times if now - t < 3600]
            if len(fail_times) >= max_fail:
                log.warning("一小时内已失败 %d 次，为避免账号被锁，暂停 10 分钟", len(fail_times))
                time.sleep(600)
                fail_times.clear()
                continue

            log.info("检测到未认证（%s），开始登录", detail)
            ok, msg = do_login(cfg, portal_url)
            if ok:
                if verify_online():
                    log.info("认证成功：%s", msg)
                    time.sleep(interval)
                    continue
                log.warning("接口返回成功但网络仍不通：%s", msg)
            else:
                log.warning("认证失败：%s", msg)
                if any(k in msg for k in ("密码", "锁定", "停用", "欠费", "用户名不存在")):
                    log.error("疑似账号问题，请手动打开认证页核对；暂停 30 分钟")
                    time.sleep(1800)
                    continue

            fail_times.append(time.time())
            time.sleep(retry)

        except KeyboardInterrupt:
            log.info("收到退出信号，守护进程结束")
            return 0
        except Exception as e:
            log.exception("守护进程异常：%s", e)
            time.sleep(30)


# --------------------------------------------------------------------------
# 命令行
# --------------------------------------------------------------------------
def cmd_status():
    cfg = load_config()
    print("程序目录 :", BASE_DIR)
    print("账号     :", cfg.get("username") or "（未配置）")
    print("密码     :", "已保存" if cfg.get("password_dpapi") else "未保存")
    print("服务类型 :", cfg.get("service") or "（默认）")
    ssid = current_ssid()
    print("当前 WiFi:", ssid if ssid else ("未连接/有线" if ssid == "" else "未知"))
    state, portal, detail = probe()
    print("网络状态 :", "已联网" if state == "online" else "未认证/无网络", f"（{detail}）")
    if portal:
        print("认证页   :", portal[:140])
    print("日志文件 :", LOG_DIR / "autologin.log")


def cmd_setup():
    cfg = load_config()
    print("=" * 56)
    print(" 校园网自动认证 · 首次配置")
    print("=" * 56)
    print("账号就是你登录校园网用的学号/工号。\n")

    cur = cfg.get("username", "")
    prompt = f"学号/工号 [{cur}]: " if cur else "学号/工号: "
    name = input(prompt).strip() or cur
    if not name:
        print("账号不能为空，已取消。")
        return 1

    import getpass
    pwd = getpass.getpass("密码（输入时不显示）: ")
    if not pwd:
        print("密码不能为空，已取消。")
        return 1

    svc = input(f"服务类型（多数情况留空即可）[{cfg.get('service','')}]: ").strip()
    cfg["username"] = name
    cfg["service"] = svc or cfg.get("service", "")
    try:
        cfg["password_dpapi"] = protect(pwd)
        cfg["password_plain"] = ""
    except Exception as e:
        print("DPAPI 加密不可用，将以明文保存（不推荐）：", e)
        cfg["password_plain"] = pwd
        cfg["password_dpapi"] = ""
    save_config(cfg)
    print("\n已保存到", CONFIG_PATH)

    state, portal, detail = probe()
    print("\n当前网络：", "已联网" if state == "online" else f"未认证（{detail}）")
    if state == "online":
        print("无需登录。配置已生效，开机后会自动检查。")
    else:
        print("\n现在试登录一次……")
        ok, msg = do_login(cfg, portal)
        if ok and verify_online():
            print("✅ 登录成功：", msg)
        else:
            print("❌ 登录失败：", msg)
            print("   请把日志发我：", LOG_DIR / "autologin.log")
            return 1

    if start_now():
        print("\n后台守护进程已启动：断线会自动重连，可直接关闭此窗口。")
    return 0


def _pythonw():
    """挑选一个稳定的 pythonw.exe：优先系统安装的 Python，避免宿主程序升级/卸载后路径失效。"""
    roots = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python",
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")),
    ]
    found = []
    for root in roots:
        if root.is_dir():
            found += sorted(root.glob("Python3*/pythonw.exe"), reverse=True)
    if found:
        return str(found[0])
    return str(Path(sys.executable).resolve().with_name("pythonw.exe"))


def start_now():
    """立即在后台启动守护进程，不必等下次开机。已运行则返回 False。"""
    probe_lock = acquire_single_instance()
    if probe_lock is None:
        return False
    probe_lock.close()

    subprocess.Popen(
        [_pythonw(), str(BASE_DIR / "autologin.py"), "--daemon"],
        cwd=str(BASE_DIR),
        creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    # 确认子进程真的把单实例锁拿到了，否则视为启动失败
    for _ in range(12):
        time.sleep(0.4)
        check = acquire_single_instance()
        if check is None:
            return True
        check.close()
    return False


def cmd_install():
    """注册开机自启：优先计划任务，失败回退到「启动」文件夹。"""
    script = BASE_DIR / "autologin.py"
    pythonw = _pythonw()
    task = APP_NAME

    ps = f"""
$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute '{pythonw}' -Argument '"{script}" --daemon' -WorkingDirectory '{BASE_DIR}'
$t = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\\$env:USERNAME"
$t.Delay = 'PT15S'
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
      -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
      -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
      -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName '{task}' -Action $a -Trigger $t -Settings $s -Force `
      -Description 'Campus network auto login (Ruijie ePortal)' | Out-Null
Write-Output 'TASK_OK'
"""
    encoded = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    print("正在注册计划任务（开机/登录时自动运行）……")
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", encoded],
        capture_output=True, text=True, encoding="mbcs", errors="ignore",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if "TASK_OK" in (r.stdout or ""):
        print("✅ 已注册计划任务：", task)
        print("   开机登录后约 15 秒开始自动认证，之后每 15 秒检查一次。")
        if start_now():
            print("   后台守护进程已启动，现在就生效。")
        return 0

    print("计划任务注册失败，改用「启动」文件夹方式。")
    print("  原因：", ((r.stderr or r.stdout) or "").strip()[:300])
    startup = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup"
    vbs = startup / f"{APP_NAME}.vbs"
    vbs.write_text(
        'Set sh = CreateObject("WScript.Shell")\r\n'
        f'sh.CurrentDirectory = "{BASE_DIR}"\r\n'
        f'sh.Run """{pythonw}"" ""{script}"" --daemon", 0, False\r\n',
        encoding="mbcs",
    )
    if vbs.exists():
        print("✅ 已写入启动项：", vbs)
        if start_now():
            print("   后台守护进程已启动，现在就生效。")
        return 0
    return 1


def cmd_uninstall():
    ps = f"Unregister-ScheduledTask -TaskName '{APP_NAME}' -Confirm:$false -ErrorAction SilentlyContinue"
    encoded = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    vbs = Path(os.environ["APPDATA"]) / f"Microsoft/Windows/Start Menu/Programs/Startup/{APP_NAME}.vbs"
    if vbs.exists():
        vbs.unlink()
    # 结束正在运行的守护进程
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*autologin.py --daemon*' } "
         "| ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"],
        capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    print("✅ 已取消开机自启，并停止后台进程。")
    return 0


def cmd_capture():
    """断网时运行：把当前被劫持的认证页原样存下来，便于定位解析问题。"""
    cfg = load_config()
    print("正在探测并抓取认证页……")
    state, portal, detail = probe(cfg.get("request_timeout", 6), cfg)
    print("状态  :", "已联网" if state == "online" else "未认证", f"（{detail}）")
    if state == "online":
        print("当前已联网，抓不到认证页。请在断网（未登录）状态下再运行一次。")
        return 0

    snap = DEBUG_DIR / "hijack_latest.html"
    print("快照  :", snap if snap.exists() else "（未生成）")
    print("解析出:", portal or "（无）")
    params = _hidden_params(_LAST_HIJACK.get("body") or b"")
    if params:
        print("参数  :", ", ".join(f"{k}={v}" for k, v in params.items()))
    else:
        print("参数  : 页面里没有找到 wlanuserip 等字段")
    print("\n请把 debug 目录整个打包发给开发者。")
    return 0


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description="校园网（锐捷 ePortal）自动认证")
    ap.add_argument("--daemon", action="store_true", help="后台守护：持续检测并自动登录")
    ap.add_argument("--once", action="store_true", help="只检查并尝试登录一次")
    ap.add_argument("--status", action="store_true", help="查看当前状态")
    ap.add_argument("--setup", action="store_true", help="配置账号密码")
    ap.add_argument("--install", action="store_true", help="注册开机自启")
    ap.add_argument("--uninstall", action="store_true", help="取消开机自启")
    ap.add_argument("--capture", action="store_true", help="断网时抓取认证页快照用于排查")
    ap.add_argument("--verbose", "-v", action="store_true", help="输出详细日志")
    args = ap.parse_args()

    setup_logging(verbose=args.verbose)

    if args.setup:
        return cmd_setup()
    if args.status:
        cmd_status()
        return 0
    if args.install:
        return cmd_install()
    if args.uninstall:
        return cmd_uninstall()
    if args.capture:
        return cmd_capture()
    if args.daemon:
        return run_daemon()

    # 默认：--once
    cfg = load_config()
    state, portal, detail = probe()
    if state == "online":
        log.info("当前已联网，无需认证（%s）", detail)
        print("当前已联网，无需认证。")
        return 0
    log.info("当前未认证：%s", detail)
    ok, msg = do_login(cfg, portal)
    if ok:
        if verify_online():
            log.info("认证成功：%s", msg)
            print("认证成功：", msg)
            return 0
        msg = f"接口返回成功，但网络仍不通（{msg}）"
    log.warning("认证失败：%s", msg)
    print("认证失败：", msg)
    return 1


if __name__ == "__main__":
    sys.exit(main())
