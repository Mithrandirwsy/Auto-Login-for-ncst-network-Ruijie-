# -*- coding: utf-8 -*-
"""端到端模拟：内容劫持（200 直出认证页）→ 自动解析参数 → 成功登录。"""
import http.server
import importlib.util
import json
import os
import threading
import urllib.parse
from pathlib import Path

# 测试环境可能带系统代理，本地回环必须直连
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_k, None)
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

BASE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("al", str(BASE / "autologin.py"))
al = importlib.util.module_from_spec(spec)
spec.loader.exec_module(al)

STATE = {"logged_in": False, "seen": []}

PORTAL_HTML = """<html><head><title>校园网认证</title></head><body>
<form id="f">
<input type="hidden" name="wlanuserip" value="10.128.45.241">
<input type="hidden" name="wlanacname" value="NCST-AC1">
<input type="hidden" name="nasip" value="10.159.255.254">
<input type="hidden" name="t" value="wireless-v2">
</form>
<div>校园网认证 请先登录</div></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        # generate_204：已登录返回 204，否则 200 直出认证页（模拟内容劫持）
        if self.path.startswith("/generate_204"):
            if STATE["logged_in"]:
                self.send_response(204)
                self.end_headers()
            else:
                self._send(200, PORTAL_HTML)
            return
        self._send(200, PORTAL_HTML)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode("utf-8")
        flat = urllib.parse.parse_qs(raw, keep_blank_values=True)
        dec = {k: urllib.parse.unquote(v[0]) for k, v in flat.items()}
        STATE["seen"].append(dec)

        qs = urllib.parse.parse_qs(dec.get("queryString", ""))
        ok = (
            dec.get("userId") == "202415750423"
            and dec.get("password") == "p@ss word&x"
            and qs.get("wlanuserip") == ["10.128.45.241"]
            and qs.get("nasip") == ["10.159.255.254"]
            and qs.get("wlanacname") == ["NCST-AC1"]
        )
        if ok:
            STATE["logged_in"] = True
            self._send(200, json.dumps({"result": "success", "message": "认证成功"}), "application/json")
        else:
            self._send(200, json.dumps({"result": "fail", "message": "用户名或密码错误"}), "application/json")


def main():
    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    cfg = dict(al.DEFAULT_CONFIG)
    cfg.update({
        "portal_hosts": ["127.0.0.1"],
        "probe_urls": [f"http://127.0.0.1:{port}/generate_204"],
        "request_timeout": 3,
        "username": "202415750423",
        "password_plain": "p@ss word&x",   # 含空格和 & ，验证双重编码
        "password_dpapi": "",
    })

    print("1) 未登录状态下自动发现并登录")
    ok, msg = al.do_login(cfg)
    print("   ->", ok, msg)
    assert ok, "应登录成功"
    assert STATE["logged_in"], "服务端应记录已登录"

    print("2) 已在线时应直接返回")
    state, portal, detail = al.probe(cfg=cfg)
    print("   ->", state, detail)
    assert state == "online"

    print("3) 密码错误分支")
    STATE["logged_in"] = False
    cfg_bad = dict(cfg, password_plain="wrong")
    ok2, msg2 = al.do_login(cfg_bad)
    print("   ->", ok2, msg2)
    assert not ok2 and "密码" in msg2

    print("4) 传入站外门户地址，应拒绝且绝不向站外提交")
    STATE["logged_in"] = False
    al._LAST_HIJACK["body"] = (
        b'<script>location.href="http://evil.example.com/eportal/index.jsp?wlanuserip=1.2.3.4"</script>'
    )
    al._LAST_HIJACK["url"] = "http://evil.example.com/x"
    assert al.discover_portal(al._LAST_HIJACK["body"], al._LAST_HIJACK["url"], cfg) == "", \
        "站外域名不应被解析成门户"
    assert not al.host_allowed("evil.example.com", cfg), "站外域名不应通过白名单"
    before = len(STATE["seen"])
    ok3, msg3 = al.do_login(cfg, "http://evil.example.com/eportal/index.jsp?wlanuserip=1.2.3.4")
    print("   ->", ok3, msg3)
    # 允许回退到白名单内的真实门户（本地假门户），但不能向站外地址发任何请求
    assert STATE["logged_in"], "回退后应使用白名单内的真实门户完成登录"
    assert len(STATE["seen"]) > before, "应只向白名单门户提交"

    srv.shutdown()
    print("\n端到端全部通过")


if __name__ == "__main__":
    main()
