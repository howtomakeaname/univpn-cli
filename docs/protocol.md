# Protocol scope

This document describes the supported interoperability profile. It is not a complete vendor protocol specification.

## 连接认证

```text
应用 → SOCKS5/HTTP → gVisor IPv4/TCP → TLS 数据通道 → VPN 网关 → 内网目标
                         ↑               ↑
                   获分配的虚拟 IP    TLS 控制通道负责认证与保活
```

1. 验证网关 TLS 身份。发送 340 字节 FirstConnect，携带认证域，确认 v1 响应。
2. 在同一控制连接发送密码认证：256 字节域、保留字段、用户名/密码/MAC TLV。用户名和密码按协议转义 `%`、`&`、`+` 并以 NUL 结束。MAC 为本地管理地址格式。
3. 状态 `1` 且 TLV `2` 的值为 `01` 表示需要短信/邮箱验证码。第二因子请求使用命令 `02`，长度 33，内容为子类型 `01` 加 32 字节 NUL 填充的验证码字段。完成后仍返回认证命令 `01`。
4. 最终成功状态 `0` 后，TLV `3` 提供会话令牌。命令 `03` 用令牌申请虚拟 IPv4。
5. 建立第二条、同样验证证书的 TLS 连接，用命令 `64` 和令牌绑定数据通道。控制连接持续保持，令牌不单独导出或持久化。

密码策略会区分到期提醒与强制改密；仅到期提醒不会中断已成功认证的会话。

## 帧与流量转发

TLS 内的帧头如下，多字节整数为大端：

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 4 | `c1 92 a4 d6` |
| 4 | 1 | 版本 `01` |
| 5 | 1 | 命令 |
| 6 | 2 | 负载长度 |
| 8 | 可变 | 负载 |

TLV 是 16 位类型、16 位长度及值。帧读取使用 `io.ReadFull`，完整处理 TLS 分片；收到不支持的帧或通道错误会停止会话。

| 通道 | 命令 | 内容 |
| --- | --- | --- |
| 控制 | `06` | 32 字节令牌＋毫秒计数，每 10 秒 |
| 数据 | `65` | 空负载保活，每 15 秒 |
| 数据 | `66` | 8 字节保留字段＋完整 IPv4 包 |

gVisor 处理 TCP 重传、乱序、窗口、SACK 和并发，应用套接字全部在用户态网络栈中。数据发送将已排队的最多 32 个帧合并为 TLS 写入，不引入聚合等待定时器；写锁防止保活和数据交错。队列、最大连接数、帧尺寸和读写等待均有上限。主机只建立到 VPN 网关的外层网络连接与本地代理监听，不安装内网系统路由。

## References

上游 OpenConnect 当前列出的协议中没有原生 UniVPN 支持，不能直接套用 AnyConnect 或 Fortinet 选项：[OpenConnect 协议列表](https://www.infradead.org/openconnect/protocols.html)。

公开独立项目记录了相符的 v1 帧和双 TLS 通道，但其文档明确说明尚未实现 MFA：[UniVPN Connect 协议记录](https://github.com/Bruce-lhq/univpn-connect/blob/main/docs/protocol.md)。本项目的 MFA 和代理路径另行验证。公开记录描述的是部分兼容性，不能推广为完整厂商协议规范。

UDP/DTLS、旧版 HTTP 认证路径、端点合规、会话续期和其他网关版本尚未实现；不尝试跳过 MFA 或网关的端点检查要求。
