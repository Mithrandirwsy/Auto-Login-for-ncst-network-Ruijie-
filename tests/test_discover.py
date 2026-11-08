# -*- coding: utf-8 -*-
"""劫持页解析的单元测试：覆盖 302 之外的各种“内容劫持”形态。"""
import importlib.util
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("al", str(BASE / "autologin.py"))
al = importlib.util.module_from_spec(spec)
spec.loader.exec_module(al)

cfg = al.load_config()

META = """<html><head><meta http-equiv="refresh" content="0;url=http://172.30.0.11/eportal/index.jsp?wlanuserip=10.128.45.241&wlanacname=NCST-AC1&nasip=10.159.255.254&mac=aa:bb&t=wireless-v2&url=http%3A%2F%2Fwww.baidu.com"></head>
<body>校园网认证 请先登录</body></html>"""

JS = """<html><body>请先认证<script>top.location.href="http://login.ncst.edu.cn/eportal/index.jsp?wlanuserip=10.128.45.241&amp;nasip=10.159.255.254&amp;t=wireless-v2";</script></body></html>"""

FORM = """<html><body><form>
<input type=hidden name="wlanuserip" value="10.128.45.241">
<input type=hidden name="wlanacname" value="NCST-AC1">
<input type=hidden name="nasip" value="10.159.255.254">
<input type="hidden" value="wireless-v2" name="t">
</form>校园网登录</body></html>"""

GBK = """<html><body>请先认证 登录<script>
var wlanuserip = "10.128.45.241"; var nasip = "10.159.255.254"; var wlanacname="NCST-AC1";
</script></body></html>"""

EVIL = """<html><body><script>location.href="http://evil.example.com/eportal/index.jsp?wlanuserip=1.2.3.4";</script></body></html>"""

cases = [
    ("meta refresh 跳转", META.encode("utf-8")),
    ("JS 跳转 + &amp;", JS.encode("utf-8")),
    ("门户页直出（隐藏表单）", FORM.encode("utf-8")),
    ("GBK 页面 + JS 变量", GBK.encode("gbk")),
    ("站外域名（应拒绝）", EVIL.encode("utf-8")),
]

ok_all = True
for name, body in cases:
    got = al.discover_portal(body, "http://connect.rom.miui.com/generate_204", cfg)
    params = al._hidden_params(body)
    print(f"[{name}]")
    print("   解析:", got or "（无）")
    print("   参数:", params or "（无）")
    if "evil" in (got or ""):
        print("   !! 白名单失效")
        ok_all = False

# 关键断言：可解析的用例都必须带 wlanuserip
for name, body in cases[:4]:
    got = al.discover_portal(body, "http://connect.rom.miui.com/generate_204", cfg)
    assert got and "wlanuserip=" in got, f"{name} 未取到 wlanuserip: {got}"

assert al.discover_portal(cases[4][1], "", cfg) == "", "站外域名应被拒绝"
print("\n全部断言通过" if ok_all else "\n存在失败项")
