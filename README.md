# 校园网自动认证（锐捷 ePortal）

Windows 开机自动登录校园网的小工具。不用再打开浏览器手动点登录，掉线也会自动重连。

为华北理工大学 `ncst.edu.cn`（锐捷 RG-SAM+ ePortal）实测可用，原理通用，改配置即可适配其他使用锐捷网页认证的学校。

纯 Python 标准库实现，**零第三方依赖**。

## 特性

- **两种劫持形态都能处理**：302 跳转到认证页，或 200 直接返回认证页 HTML（内容劫持）
- **开机自启**：注册计划任务，登录 Windows 后约 15 秒开始认证
- **掉线自动重连**：每 15 秒探测一次，开销约几 KB
- **密码用 Windows DPAPI 加密**，磁盘上没有明文
- **严格白名单**：只对配置的门户域名提交密码，换到咖啡厅/酒店 Wi-Fi 绝不会把密码发给第三方
- **防锁号**：一小时内最多失败 4 次，遇到密码类错误停 30 分钟

## 快速开始

需要 Windows + Python 3.8 及以上（装 Python 时勾选 "Add python.exe to PATH"）。

| 步骤 | 操作 |
| --- | --- |
| 1 | 把本项目放到一个固定目录（别放临时目录，例如 `D:\Tools\campus-net`） |
| 2 | 双击 `setup.bat`，输入学号/工号和密码 |
| 3 | 双击 `install_autostart.bat`，注册开机自启 |

之后开机就会自动认证。任何时候双击 `status.bat` 看当前状态。

> 顺序反了也没事：守护进程会等你配置好账号。

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `autologin.py` | 主程序（全部逻辑都在这里） |
| `config.json` | 你的配置，由 `setup.bat` 生成，**已在 .gitignore 中，不要提交** |
| `config.example.json` | 配置模板 |
| `setup.bat` | 配置账号密码 |
| `status.bat` | 查看当前状态 |
| `login_now.bat` | 立刻检查并登录一次 |
| `install_autostart.bat` | 注册开机自启并立刻在后台启动 |
| `remove_autostart.bat` | 取消开机自启并停止后台进程 |
| `capture.bat` | 排障：把被劫持的认证页原样存到 `debug/` |
| `logs/autologin.log` | 运行日志（自动轮转，保留 3 份） |

命令行等价用法：

```bat
python autologin.py --setup        :: 配置账号
python autologin.py --status       :: 查看状态
python autologin.py --once         :: 登录一次
python autologin.py --daemon       :: 后台守护（自启用的就是它）
python autologin.py --install      :: 注册自启
python autologin.py --uninstall    :: 取消自启
python autologin.py --capture      :: 抓取认证页快照（排障）
```

## 工作原理

锐捷 ePortal 的网页认证，本质是这么一个请求：

```
POST /eportal/InterFace.do?method=login
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

userId=...&password=...&service=...&queryString=...&passwordEncrypt=false
```

其中 `userId`、`password`、`queryString` 都要**双重 URL 编码**（`encodeURIComponent` 两次），
而 `queryString` 里必须带 AC 分配的设备参数：

```
wlanuserip=10.x.x.x&nasip=...&wlanacname=...&mac=...&t=wireless-v2&url=...
```

**这些参数不能自己拼。** 按本机 IP 硬构造会被门户直接判为
`设备未注册,请在ePortal上添加认证设备`（实测验证过）。只能从 AC 返回的认证页里原样取回来。

于是整个流程是：

1. 请求 `http://connect.rom.miui.com/generate_204` 之类的探测地址；
   - 返回 204 / 正常内容 → 已联网，继续睡；
   - 返回认证页 → 未认证，进入第 2 步。
2. 从认证页里取出真门户地址与设备参数。支持四种线索：
   - `302 Location` 头；
   - `<meta http-equiv="refresh" content="0;url=...">`；
   - JS 跳转（`location.href = "..."`）；
   - 页面里直接嵌的隐藏表单字段（`<input name="wlanuserip" ...>`）或 JS 变量。
3. 用取到的参数调上面那个接口提交认证。
4. 再探测一次确认网络真通了，才算成功（接口说成功但网络不通的情况是存在的）。

## 安全设计

- 密码用 Windows **DPAPI** 加密后存 `config.json`，只有当前 Windows 用户能解密，
  换用户、换电脑都解不开；配置文件里没有明文密码。
- **门户白名单**：认证页主机必须是 `portal_hosts` 里列出的地址，否则拒绝提交，
  并写日志。在陌生网络下宁可失败也不会泄露密码。
- **SSID 白名单**：只在指定 Wi-Fi（默认 `ncst.edu.cn`）下工作，其他网络自动挂起。
- **失败退避**：一小时内最多 4 次，密码类错误直接停 30 分钟，避免把账号刷锁。
- 单实例锁，不会越开越多。

## 适配其他学校

编辑 `config.json`：

```json
{
  "username": "你的学号",
  "ssid_whitelist": ["你的校园网SSID"],
  "portal_hosts": ["认证门户IP或域名"],
  "service": ""
}
```

`portal_hosts` 一定要填准，它是白名单——填错了程序会拒绝登录（这是有意设计）。
不知道怎么填？断开网络后在浏览器里随便访问一个 http 网站，看跳转到的认证页地址即可。

`service` 是部分学校的"服务类型"（校园网/移动/联通/电信）。留空即可；
如果你们学校要选，在浏览器登录页按 F12 看 `net_access_type` 的 value 填进来。

## 排障

| 现象 | 处理 |
| --- | --- |
| 提示"未取到认证页参数" | 断网状态下双击 `capture.bat`，把 `debug/` 发出来看认证页结构 |
| 提示"认证页域名不在白名单内" | `config.json` 的 `portal_hosts` 与实际门户不符 |
| 提示"设备未注册" | 说明设备参数没取到，同第一条 |
| 说成功但网还是不通 | 看 `logs/autologin.log` 里接口的原始返回 |
| 要卸载 | 双击 `remove_autostart.bat`，然后删掉整个文件夹 |

日志在 `logs/autologin.log`，接口返回、失败原因都记在里面。

## 测试

不需要真实账号，也不需要断网，纯本地跑：

```bash
python tests/test_discover.py   # 认证页解析：5 种劫持形态（meta refresh / JS 跳转 / 隐藏表单 / GBK / 站外域名）
python tests/test_e2e.py        # 端到端：起一个本地假 ePortal，验证自动发现参数、登录成功、密码错误、站外拒发
```

## 已知限制

- 只支持 Windows（依赖 DPAPI 与计划任务）；Linux/macOS 需自行替换密码存储与自启方式。
- 只适配锐捷 ePortal。深澜（srun）、Dr.COM 等认证系统的接口不同，需要另写。
- 学校如果启用了验证码或密码 RSA 加密（`passwordEncrypt=true`），当前实现不覆盖。

## 免责声明

仅供个人在自己账号上免去重复手动登录。请遵守所在学校的网络使用规定。
密码仅保存在本机，不会发往除你学校认证门户以外的任何地址。

## License

MIT
