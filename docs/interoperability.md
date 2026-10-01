# WS63 双角色加密互通

在 ANTSDR E310 v1 上运行 G 或 T 程序，与 WS63 官方 SDK 1.10.108 的 UART 对端交换加密数据。先完成 [E310 构建](e310-source.md) 和 [WS63 固件准备](ws63-build.md)。

## 选择角色

按 WS63 对端选择 E310 程序：

| E310 程序 | WS63 对端 | 业务方向 |
| --- | --- | --- |
| `sle_gnode` | 官方 SDK 1.10.108 的 UART server，属性增加 WRITE 权限 | E310 发起连接、配对、SSAP 发现与加密写入；接收 WS63 通知 |
| `sle_tnode` | 官方 SDK 1.10.108 的 UART client | E310 广播并接受连接、配对；接收加密写入并发送通知 |

WS63 server 必须增加 WRITE 声明，修改位置见 [WS63 固件准备](ws63-build.md)。client 使用官方 UART 示例。

以下命令采用 `standard` 资源字布局和 `0x200` 配对参数，以匹配 SDK 1.10.108。`0x200` 选择计数和会话密钥派生方式，不是固定密钥；实际密钥由运行时生成，见 [密钥生成说明](key-generation.md)。

## 运行前提

先按 [构建文档](e310-source.md) 生成 ARM 程序，并放到 E310 的可执行目录。以下命令在 **E310 Linux 终端**执行，会使用无线设备。电脑上的 host 构建主要用于离线测试，不用于代替目标板运行。

需要匹配的 SD 启动系统、IIO mmap DMA 驱动和 CPU 亲和性配置，见 [硬件说明](hardware.md)。每次只运行一个无线程序，WS63 选择相反角色。串口工具必须连接正确的 WS63 UART 端口；开始新会话前重新启动对端，避免前次连接状态干扰。

进入存放 ARM 可执行文件的目录后执行以下命令。增益值是示例参数，需结合实际射频环境确认。

## E310 G 交互连接 WS63 server

确认 WS63 运行增加 WRITE 声明的 server 固件，再启动 G；日志写入新建的板上临时目录：

```sh
run_dir=$(mktemp -d /tmp/sle-g-chat.XXXXXX)
./sle_gnode \
  --interactive 1 --attempts 1 --seconds 60 --connect-seconds 25 \
  --resource-layout standard --pair-variant 0x200 \
  --tx-gain -10 --rx-gain 30 --tx-cfo-hz 0 \
  --ssap-mtu 520 \
  --log "$run_dir/session.jsonl" --event-log "$run_dir/events.jsonl"
```

按以下顺序检查同一连接内的双向业务：

1. 等待 G 显示“已连接并加密（MTU …）”。
2. 在 G 输入 `G-HELLO-001` 并回车，确认收到成功写入响应，且 WS63 server UART 显示对应内容。
3. 在 WS63 UART 输入 `SERVER-REPLY-001` 并回车，检查 G 的 `[WS63 -> E310]` 输出。
4. 在 G 输入 `G-HELLO-002`，确认同一连接可以再次写入。

### G 的输入与退出行为

每行最多 **46 字节**，自动追加 CRLF，最多形成 48 字节写值；中文按 UTF-8 字节计数。超长行、含 NUL 的行或超出协商 MTU 的行会整行拒绝。每次只有一个 WRITE_REQ 在途，收到响应后才处理下一行；等待响应超过 5 秒结束该次连接尝试。“已排队”不代表对端已收到，成功 WRITE 响应也不等同于业务回显。

交互模式自动启用配对，未指定时使用最大传输单元（MTU）520，不能同时指定 `--ssap-write`。建连、配对和属性发现受 `--connect-seconds` 限制；就绪后连接最长持续 24 小时，校准、时序、消息完整性校验（MIC）和监督超时检查仍可能提前结束连接。

使用 Ctrl-C 退出并清理设备。标准输入结束（EOF）只停止读取；G 继续处理已缓冲的完整行和在途响应，随后保持连接，未换行尾部不发送。交互模式被 Ctrl-C 中断时通常返回 1，须结合 `reason/result=signal` 与 `cleanup` 检查；该退出码不表示已完成的业务失败，也不会把 `acceptance.ok` 或 `milestone_observed` 自动置为 true。

两角色收到 SIGINT（Ctrl-C）、SIGTERM、SIGHUP 或 SIGPIPE 时均停止并走清理路径。示例采用 `--attempts 1`；若显式允许重连，已读入但尚未发送的完整行与半行会保留到下一连接，EOF 状态也会保留。G 不重发断线时结果未知的在途 WRITE，避免自动重复业务；需要确认对端记录后再决定是否手动补发。

### G 的日志

主日志和可选 event-log 在交互模式中分别使用 32 MiB、256 KiB 有界内存缓冲，**停止射频后才落盘，不可通过 tail event-log 驱动实时交互**。应根据实时控制台提示操作；不要 `kill -9`，否则内存日志可能丢失。终端输出采用非阻塞模式，结束时检查 `dropped_display_bytes`。通知中的控制字符以 `\xHH` 显示，完整字节记录在 `ssap_notify.value_hex`。

### G 的一次性自动写入

需要自动发送一条写入时，使用非交互模式：

```sh
run_dir=$(mktemp -d /tmp/sle-g-once.XXXXXX)
./sle_gnode \
  --attempts 1 --seconds 20 --connect-seconds 25 --hold-seconds 17 \
  --resource-layout standard --pair-variant 0x200 \
  --tx-gain -10 --rx-gain 30 --tx-cfo-hz 0 \
  --ssap-mtu 520 --ssap-write G108-HELLO \
  --log "$run_dir/session.jsonl" --event-log "$run_dir/events.jsonl"
```

非交互模式仍提供实时事件文件；交互模式的日志缓冲规则不要套用到它。对成功响应检查 `ssap_write_rsp.ok=true`、`protected=true`；两字节成功响应不带显式状态字段时日志 `status=-1`，不能只按状态数值判断失败。

## E310 T 接受 WS63 client

确认 WS63 运行官方 UART client，再启动 T 等待连接：

```sh
run_dir=$(mktemp -d /tmp/sle-t-chat.XXXXXX)
./sle_tnode \
  --attempts 1 --seconds 20 --connect-seconds 25 \
  --reply-mode predictive --resource-layout standard --pair-variant 0x200 \
  --notify-prefix SLE-SERVER --tx-gain -10 --rx-gain 30 \
  --local-mtu 520 --tx-frag 24 --interactive 1 \
  --log "$run_dir/session.jsonl"
```

等待 T 显示“已连接并加密（MTU …）”后，再检查双向业务：

1. 在 T 前台终端输入一行文本，确认 WS63 client UART 显示相应通知载荷。
2. 从 WS63 UART 输入另一行，确认 T 显示接收到的加密写入。
3. 完成后按 Ctrl-C，让程序完成设备清理；检查退出原因和清理结果。

### T 的输入与日志行为

T 同样在 EOF 后保持连接，文本分段和日志行为与 G 有以下区别：

- T 按 `min(协商 MTU - 6, 512)` 限制每个通知值，并为文本追加 CRLF；较长输入按可容纳的正文长度分段发送，不采用 G 的 46 字节整行拒绝规则。
- G/T 的 stdin EOF 均不自动结束连接，统一使用 Ctrl-C 退出；通常返回 1，且记录 signal 原因。T 清理结果查看 `cleanup.restore_result`，G 查看 `cleanup.attributes_restored`，不能只靠退出码判断业务是否成功。
- T 的输入实现把一次读取的非正返回视为 EOF，不区分暂时错误；G 对暂时读取错误会重试。遇到输入异常时，检查输入源并重新启动会话。
- T 同步输出终端内容，收到的写值按原始字节显示。日志在业务就绪、交互日志缓冲超过 4 MiB 或一次连接尝试结束时写出，没有固定时间周期；日志文件暂未更新不能单独作为通信停滞的依据。它不具备 G 的非阻塞终端丢弃计数与控制字符转义，缓慢的输出端可能影响实时调度。因此在前台终端运行，日志放板上 `/tmp`，不把交互模式用作时序或吞吐基准。
- “通知已排队”只说明通知进入发送队列，不能替代 WS63 实际接收证据。T 的交互连接预算最长 24 小时，射频/协议错误仍可能提前终止；`--connect-seconds` 的短建连预算行为不能照搬 G。

上述命令使用 24 字节发送分片，并执行 MTU 协商、配对和传输计数检查。官方 UART client 可能把串口输入分成多个短 SSAP 写入；这不等于验证了单个长 SSAP 写入。接入失败、校准失败或缺少本地发送完成证据（TX witness）仍可能中止连接；失败时检查会话日志中的原因。

## 双向业务验收

仅看到连接、配对或“已排队”不算双向业务成功。在同一次连接尝试（attempt）内核对两端实际业务字节、成功写入响应、通知载荷与 MIC 结果。WS63 UART 示例可能将一次输入拆成多个通知或写入，按顺序拼接后比较 `value_hex`，不要只看截断的 `text` 字段。结合 `pair_final` 的加密状态和 MIC 计数判断；不同方向的日志字段以各程序实际输出为准。

## 验证边界

已有二进制的验证结果见 [双角色交互验证](validation-results.md)，覆盖同会话重复双向加密传输、EOF 后继续接收与信号清理。具体二进制及试验限制单独记录在 [当前状态](source-status.md)；验证结论仅适用于记录中的二进制和试验条件。该短功能回归与离线测试均不替代长期稳定性、吞吐或标准时序符合性验收。

需要定位失败环节时，结合 [协议栈说明](protocol-stack.md) 阅读日志；检查配对和加密边界时，参阅 [安全说明](security.md)。
