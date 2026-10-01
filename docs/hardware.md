# 硬件与调试配置

运行 [E310 双角色程序](interoperability.md) 前，先准备 ANTSDR E310 **v1**、WS63 对端和匹配的板上系统。本页说明运行条件及工程内的可选调试配置。

## E310 运行条件

程序使用 AD9361 和 Linux IIO 的 mmap DMA 接口，以内存映射方式访问采样缓冲区。板上内核、IIO 驱动、设备树和 FPGA 数据通路必须匹配；本工程不提供 SD 启动镜像、FPGA 位流或系统固件。

程序通过 [`sle_iio.h`](../sle-rt/sle_iio.h#L18) 中的固定路径访问设备，不自动发现 IIO 编号。运行前核对板上的映射：`iio:device0` 为 AD9361 PHY，`iio:device2` 为 TX，`iio:device3` 为 RX；TX/RX 设备节点分别为 `/dev/iio:device2` 和 `/dev/iio:device3`。编号不一致时，需适配这些路径定义并重新构建。

运行账户需具备 `SCHED_FIFO` 实时调度、`mlockall` 内存锁定、IIO sysfs 属性写入和 IIO 设备读写权限，通常使用 root。使用非 root 账户时，需预先配置相应权限和资源限制；实时调度或内存锁定失败会使程序在无线初始化前退出，见 [`sle_iio_realtime`](../sle-rt/sle_iio.c#L153)。启用 `--hw-status 1` 时还需要 `/dev/mem` 访问权限。

运行环境需启用双核，并为实时线程预留 CPU1，例如在启动参数中配置 `isolcpus=1`。程序默认将实时无线线程放在 CPU1、控制线程放在 CPU0；同一台 E310 每次只运行一个 G 或 T 程序。

使用已准备好的 SD 启动系统，不擦写 QSPI，也不要向 USB 模拟配置盘写入文件。接线采用 E310 RX1 接天线、与 WS63 空中通信；改变射频连接方式前先核对输入功率。WS63 的角色和 UART 引脚见 [WS63 固件准备](ws63-build.md)。

## 可选 WS63 调试配置

工程提供两份 OpenOCD 配置，供已有 WS63 SWD 调试环境使用。运行 E310 程序本身不需要连接调试探针。

| 文件 | 用途 |
| --- | --- |
| [`ws63-jlink.cfg`](../hardware/ws63-jlink.cfg) | 支持 WS63 的 OpenOCD 配合 J-Link/SWD |
| [`ws63-cmsis-dap.cfg`](../hardware/ws63-cmsis-dap.cfg) | 支持 WS63 的 OpenOCD 配合 CMSIS-DAP/SWD |

下面的示例用于连接 WS63 调试探针，会访问硬件。执行前须准备支持 WS63 的 OpenOCD、与其版本匹配的 Tcl 目录和已接好的探针。在工程根目录运行，并替换这些占位值：

- `OPENOCD_PATH`：OpenOCD 可执行文件的绝对路径。
- `OPENOCD_TCL_DIR`：包含 `interface/` 与 `target/ws63.cfg` 的 Tcl 目录。
- `YOUR_PROBE_SERIAL`：目标探针的实际序列号。

```sh
"OPENOCD_PATH" -s "OPENOCD_TCL_DIR" \
  -c 'set PROBE_SERIAL YOUR_PROBE_SERIAL' \
  -c 'set ADAPTER_KHZ 1000' \
  -f hardware/ws63-jlink.cfg
```

使用 CMSIS-DAP 时，将最后一项换为 `hardware/ws63-cmsis-dap.cfg`。同时连接两个探针时，必须分配不同的 gdb/tcl/telnet 端口。两份配置仅监听本机，并将 `WS63_FLASH` 默认设为 `0`；实际 Flash 支持由外部 `target/ws63.cfg` 处理。

固件写入前确认板子身份和固件哈希。SWD 写入前做全片备份，写后完整读回校验；暂停 CPU 的调试流程须在错误路径也恢复运行。此处的连接示例不包含固件写入步骤。

硬件就绪后，按 [互通说明](interoperability.md) 运行对应角色。构建方法见 [E310 构建与离线测试](e310-source.md)；这份准备清单不构成对其他硬件、驱动或位流的兼容性验证。
