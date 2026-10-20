# allinone

[![test](https://github.com/Jackchen0514/all-in-one/actions/workflows/test.yml/badge.svg)](https://github.com/Jackchen0514/all-in-one/actions/workflows/test.yml)

**Hysteria2 + AnyTLS + Shadowsocks** 的多节点统一管理面板：一个用户、一套到期时间 / 流量限额 / 流量倍数 / 月度重置，一个订阅链接同时输出三种协议的全部节点。

由三个项目整合而来：

| 原项目 | 在 allinone 里的角色 |
|---|---|
| [hysteria-manager](https://github.com/Jackchen0514/hysteria-manager) | 面板本体（零依赖 Python）、Hysteria2 节点对接方式（HTTP 认证 + 流量统计 API + `hy2mgr-node-sync`），原样保留 |
| [anytls-go](https://github.com/Jackchen0514/anytls-go) | 节点端：`anytls-server` 二进制（Release 下载），用户由 `allinone-agent` 通过它本机的管理 API 下发 |
| [ssmanager](https://github.com/Jackchen0514/ssmanager) | 节点端：shadowsocks-rust 的 `ssmanager`（Release 下载），端口由 `allinone-agent` 通过本机 UDP manager 协议下发；原 Node.js / Vue 面板退役 |

- **面板零依赖**：Python 3.8+ 标准库（sqlite3 + http.server）
- **节点只需要出站访问面板**：anytls / ss 节点由 agent 主动拉取，面板不需要连节点（hysteria2 节点仍沿用原来的统计 API 拉取方式）
- **可以从三个旧项目平滑迁移**，见[迁移](#从旧项目迁移)

## 一键安装

```bash
# 面板 + 本机三种协议节点
bash <(curl -fsSL https://raw.githubusercontent.com/Jackchen0514/all-in-one/main/install.sh) all \
     --domain panel.example.com --node-domain hk.example.com --cf-token <CF_TOKEN> --email you@mail.com

# 在其他服务器上加节点（默认三种协议都装，--type 可选其中几种）
bash <(curl -fsSL https://raw.githubusercontent.com/Jackchen0514/all-in-one/main/install.sh) node \
     --domain jp.example.com --cf-token <CF_TOKEN> --email you@mail.com \
     --panel https://panel.example.com --api-token <面板 API Token> --name 日本 \
     [--type hysteria2,anytls,ss] [--obfs] [--hop 20000-30000] [--anytls-port 443] [--ss-method aes-256-gcm]

# 只装面板
bash install.sh panel --domain panel.example.com --cf-token <CF_TOKEN> --email you@mail.com

# 卸载
bash install.sh uninstall panel|node
```

Cloudflare API Token 权限：**Zone · Zone · Read** + **Zone · DNS · Edit**。脚本会把域名 A 记录指向本机（仅 DNS，不开小黄云）、用 Let's Encrypt DNS-01 签发证书。`bash install.sh --help` 查看全部参数，缺少的参数会交互式询问，重复执行不会改变密码 / Token / 端口。

| 组件 | 端口 | 证书 |
|---|---|---|
| 面板 | TCP 443（`--panel-port`） | acme.sh，`/etc/allinone/certs/<域名>/`，自动续期 |
| Hysteria2 | UDP 443（`--port`）、统计 API TCP 9999（只对面板开放） | hysteria 内置 ACME |
| AnyTLS | TCP 443；与面板同机且面板占用 443 时默认 8443（`--anytls-port`） | 与面板共用 `/etc/allinone/certs/<域名>/` |
| Shadowsocks | 每个用户一个端口，TCP+UDP，默认 40000-49999（面板 `AIO_SS_PORT_RANGE`） | 不需要 |

本机 ufw / firewalld 会自动放行（SS 端口由 agent 在下发时放行），**云服务器安全组需要自己放行**，安装结束会打印需要放行的列表。

## 一键更新

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Jackchen0514/all-in-one/main/update.sh)
```

在面板和每台节点上执行，自动识别本机装了什么：面板先备份数据库（保留 10 份）、新版本起不来自动回滚；节点更新 `hy2mgr-node-sync` / `allinone-agent`，并把 hysteria、anytls-server、shadowsocks-rust 升级到最新版（起不来自动回滚）。`--no-hysteria` / `--no-anytls` / `--no-ss` 跳过对应的升级，`--force` 强制重装面板代码。

## 工作原理

```
                               allinone 面板 (用户 / 节点 / 流量 / 订阅)
                 ┌───────────────────────┬──────────────────────────┬───────────────────────────┐
     ② POST /hy2/auth/<token>   ③ GET /traffic /online     GET /agent/<token>/state   POST /agent/<token>/report
         (连接时认证)              POST /kick (面板拉取)        (agent 拉取应有的状态)       (agent 上报累计流量)
                 │                       │                          │                           │
        ┌────────┴───────────────────────┴───┐        ┌─────────────┴───────────────────────────┴──────┐
        │ Hysteria2 节点 (+ hy2mgr-node-sync) │        │ allinone-agent ─┬─ anytls-server  本机管理 API   │
        └────────────────────────────────────┘        │                 └─ ssmanager      本机 UDP 6100  │
                                                       └────────────────────────────────────────────────┘
```

- **一个用户 = 一个密码**：同一个连接密码用于 Hysteria2、AnyTLS、Shadowsocks；另外每个用户有一个 **SS 端口**（创建时自动分配，可手动修改），在所有 SS 节点上相同
- **Hysteria2**：与 hysteria-manager 完全一样——连接时回调面板认证，面板每 `AIO_SYNC_INTERVAL` 秒拉取流量并踢掉不合规的在线用户，禁用 / 删除 / 改密码时立即踢下线
- **AnyTLS / Shadowsocks**：`allinone-agent` 每 30 秒一轮——先上报每个用户的累计流量计数，再拉取应有状态并下发：
  - anytls：创建 / 更新 / 删除用户；不合规（过期、超额、禁用）的用户在 anytls 上被禁用并设为已过期，已建立的会话也会断开；anytls 自身的限额 / 倍数 / 重置被置为中性值，统一由面板计算
  - ss：合规用户的端口 `add`，不合规用户的端口 `remove`（连接随之断开）；ssmanager 重启后丢失的端口会自动补回
  - 生效延迟最多一个 agent 周期（约 30 秒）
- **流量**：同一用户三种协议共用一个流量池和限额。hysteria2 区分上传 / 下载；anytls 和 ss 只提供合计流量，记为下载。计入的流量 = 实际流量 × **用户流量倍数** × **节点流量倍数**（节点倍数默认 1，可在节点设置里为高级 / 低价节点单独调整，0 表示该节点不计流量）。节点第一次上报只记录基线，接管旧服务器时不会把历史流量重复计费
- 节点列表的「配置下发」：hysteria2 节点显示端口 / 混淆 / 端口跳跃是否已应用；anytls / ss 节点显示 agent 是否在线、版本和最近上报时间，agent 上报的错误显示在「流量同步」一列

## 从旧项目迁移

| 旧项目 | 怎么迁移 |
|---|---|
| hysteria-manager 面板 | 在原面板服务器上执行 `install.sh panel`（同一个面板域名）：自动复制 `/opt/hy2mgr/data/hy2mgr.db`、沿用原管理员密码和 API Token，停用旧的 `hy2mgr` 服务。已有的 hysteria 节点回调地址不变，无需改动；之后在节点上执行一次 `update.sh` 换成新的同步程序 |
| anytls-go 服务器 | 在该服务器上执行 `install.sh node --type anytls ...`：先把 anytls-go 现有用户（用户名、密码、限额、已用流量、倍数、到期、月度重置）导入面板，再接管 `anytls-server`（沿用原端口、数据库、凭据和 fallback 设置） |
| ssmanager 面板 | 在该服务器上执行 `install.sh node --type ss ...`：先把旧面板的所有端口导入为面板用户（**保留原端口和密码**，客户端无需更换；用户名取备注，非英文备注用 `ss<端口>`），沿用全局流量系数，节点加密方式取导入端口里最常用的一种，然后停用 `ssmanager-panel` |

导入时已存在的同名同密码用户会跳过（可以重复执行）；用户名或密码与面板里其他用户冲突的会跳过并在安装输出里列出原因。也可以直接调用 `POST /api/v1/import` 导入。

## 订阅

每个用户有独立订阅地址 `/sub/<token>`：

- 默认：base64 编码的链接列表（v2rayN、NekoBox、Shadowrocket 等），包含 `hysteria2://`、`anytls://`、`ss://`（SIP002）
- `?format=clash`：Clash Meta / Mihomo 配置（UA 含 clash/mihomo/stash 时自动识别），包含 `hysteria2` / `anytls` / `ss` 三种 proxy
- `?format=raw`：未编码的链接列表

响应头带 `Subscription-Userinfo`。用户被禁用、过期或超额时订阅返回空列表。

## 手动部署

```bash
# 面板
mkdir -p /opt/allinone && cp -r allinone /opt/allinone/
cp deploy/env.example /opt/allinone/.env && vi /opt/allinone/.env
cp deploy/allinone.service /etc/systemd/system/ && systemctl enable --now allinone

# anytls / ss 节点：自己运行 anytls-server（带 -api-listen / -api-key）或
# ssmanager --manager-addr 127.0.0.1:6100 -s 0.0.0.0 -U，然后
install -m 755 agent/allinone_agent.py /usr/local/bin/allinone-agent
cp deploy/agent.example.json /etc/allinone/agent.json   # 填入面板地址和节点 token（面板「服务端配置」里有）
cp deploy/allinone-agent.service /etc/systemd/system/ && systemctl enable --now allinone-agent
allinone-agent --once   # 手动跑一轮，便于排错
```

Docker：`docker build -t allinone . && docker run -d -p 8080:8080 -v /opt/allinone/data:/data -e AIO_ADMIN_PASS=xxx -e AIO_API_TOKEN=xxx -e AIO_PUBLIC_URL=https://panel.example.com allinone`

### 环境变量

旧的 `HY2M_` 前缀仍然有效。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AIO_HOST` / `AIO_PORT` | `0.0.0.0` / `8080` | 监听地址 |
| `AIO_DB` | `data/allinone.db` | SQLite 数据库路径 |
| `AIO_ADMIN_USER` / `AIO_ADMIN_PASS` | `admin` / 随机 | 管理员账号 |
| `AIO_API_TOKEN` | 空 | 固定 API Token |
| `AIO_PUBLIC_URL` | 空 | 面板对外地址，用于订阅链接和节点回调 |
| `AIO_SYNC_INTERVAL` | `60` | hysteria2 流量同步 / 踢人间隔（秒） |
| `AIO_SS_PORT_RANGE` | `40000-49999` | 自动分配 SS 端口的范围 |
| `AIO_SESSION_TTL` | `604800` | 登录 token 有效期（秒） |
| `AIO_TLS_CERT` / `AIO_TLS_KEY` | 空 | 面板直接以 HTTPS 运行 |

---

## API

所有 `/api/v1/*` 接口（除 login）需要 `Authorization: Bearer <token>`，token 为 `AIO_API_TOKEN` 或 login 返回的会话 token。出错返回 `{"error": "..."}`。

与 hysteria-manager 的 API 完全兼容，新增字段与接口：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/login` | `{"username","password"}` → `{"token","expire_at"}` |
| GET | `/api/v1/stats` | 概览统计（`nodes.by_type` 按协议计数） |
| GET | `/api/v1/settings` | `ss_port_range` 等 |
| POST | `/api/v1/sync` | 立即同步所有 hysteria2 节点 |
| GET / POST | `/api/v1/users` | 用户列表 / 创建 |
| GET / PATCH / DELETE | `/api/v1/users/{username}` | 用户详情（含全部协议的 `links`）/ 修改 / 删除 |
| POST | `/api/v1/users/{username}/extend` · `add-traffic` · `reset-traffic` · `regenerate` · `kick` | 同 hysteria-manager |
| POST | `/api/v1/users/{username}/set-traffic` | 设置已用流量，body 四选一：`{"gb": 12.5}` / `{"bytes": n}`（总量，计入下载、上传清零）、`{"upload": n, "download": n}`（按方向，字节）、`{"add_gb": -2}` / `{"add_bytes": n}`（在当前值上增减，最低 0）。超出限额会立即断开，低于限额自动恢复 |
| GET | `/api/v1/users/{username}/traffic?days=30` | 按天流量历史（所有节点合计） |
| GET / POST | `/api/v1/nodes` | 节点列表 / 创建 |
| GET / PATCH / DELETE | `/api/v1/nodes/{id}` | 节点详情 / 修改 / 删除 |
| POST | `/api/v1/nodes/{id}/sync` | 同步单个 hysteria2 节点 |
| GET | `/api/v1/nodes/{id}/config` | hysteria2：服务端 `config.yaml`；anytls / ss：`agent.json` 片段 |
| POST | `/api/v1/import` | `{"source": "anytls" \| "ssmanager", "items": [...]}`，items 为 anytls-go 的 `GET /api/users` 结果或 ssmanager 面板 `ports` 表的行 → `{"created": [...], "skipped": [{"item","reason"}]}` |

**用户新增字段**：`ss_port`（1-65535，创建时不传则自动分配，冲突返回 409）。创建 / 修改用户时也可用 `used_gb` 或 `used`（字节）直接设置已用流量。

**节点字段**：`type`（`hysteria2` / `anytls` / `shadowsocks`，默认 `hysteria2`）、`name`、`address`、`port`（hysteria2：监听端口；anytls：单个 TCP 端口；shadowsocks：忽略）、`ss_method`（`aes-256-gcm` / `aes-128-gcm` / `chacha20-ietf-poly1305`）、`traffic_multiplier`（节点流量倍数 0-100，默认 1）、`sni`、`insecure`、`enabled`、`sort`；仅 hysteria2：`hop_ports`、`hop_interval`、`obfs_password`、`api_url`、`api_secret`。

**agent 接口**（以节点 token 鉴权，供 `allinone-agent` 使用）：`GET /agent/{token}/state`、`POST /agent/{token}/report` `{"counters": {"用户名": 累计字节}, "online": n, "error": "", "version": ""}`。

```bash
TOKEN=你的API_TOKEN; P=https://panel.example.com/api/v1
# 创建用户：100GB，30 天，每月 1 号重置 —— 自动拥有三种协议的连接方式
curl -X POST $P/users -H "Authorization: Bearer $TOKEN" -d '{"username":"alice","traffic_limit_gb":100,"expire_days":30,"reset_day":1}'
# 添加一个 Shadowsocks 节点
curl -X POST $P/nodes -H "Authorization: Bearer $TOKEN" -d '{"type":"shadowsocks","name":"香港 SS","address":"hk.example.com"}'
```

## 开发

```bash
python3 -m unittest discover -s tests -t .
```

`tests/test_api.py` 是 hysteria-manager 的原测试（保证 Hysteria2 行为不变），`tests/test_multi.py` 覆盖 anytls / ss 节点、导入，并用模拟的 anytls-server 管理 API 和 ssmanager UDP 端点对 `allinone-agent` 做端到端测试。

## 已知限制

- Shadowsocks 只支持接受任意密码的 AEAD 加密方式（2022 系列需要固定长度密钥，暂不支持），一个 SS 节点上所有用户使用同一种加密方式
- anytls / ss 节点的禁用、过期、超额最多有约 30 秒延迟（一个 agent 周期）；hysteria2 的「立即踢下线」不受影响
- anytls 的 IP 数 / 连接数限制、屏蔽规则、出口分组仍在 anytls-server 本机管理 API 上配置，面板不覆盖它们
- 用户被禁用 / 超额后，ss 端口会被移除：最后一次上报到移除之间（< 30 秒）的流量可能不计入
