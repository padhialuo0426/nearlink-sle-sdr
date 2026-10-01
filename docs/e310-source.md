# E310 构建与离线测试

在 Linux 主机上构建 `sle_gnode`、`sle_tnode` 并运行离线测试；使用 ARM 交叉编译器生成 E310 程序。以下命令均从本仓库根目录执行。

## 源码布局

`sle-rt/` 仅包含两个运行程序及其共享依赖：

| 模块 | 职责 |
| --- | --- |
| `sle_gnode.c` | G 节点接入、连接、SSAP 客户端业务及交互终端 |
| `sle_tnode.c` | T 节点广播、被连接、通知及交互业务 |
| `sle_radio_core.*`、`sle_radio.*`、`sle_hwstat.*`、`sle_iio.*` | 收发调度、校准、TX witness、DMA/IIO 与可选硬件状态监控 |
| `sle_g_runtime.*`、`sle_t_runtime.*` | 两角色异步配对任务、系统随机源与加密数据路径 |
| `sle_pair.*`、`sle_t_pair.*`、`sle_crypto.*`、`sle_cmtc.*` | 配对状态机、密码学封装、CMTC 能力交换与计数 |
| `sle_ssap.*`、`sle_ssap_server.*`、`sle_sdu.*` | SSAP 编解码与服务、SDU 分片和重组 |
| `sle_phy.*`、`sle_demod.*`、`sle_gfsk.*`、`sle_t_wave.*` | 帧编解码、调制解调与 T 波形 |
| `sle_access.*`、`sle_clock.*`、`sle_link.*` | 接入参数、时钟与链路/ARQ |
| `../tests/`（工程根目录的 `tests/`） | 对上述功能的离线合成回归、模拟设备测试与配对 oracle |

运行程序不链接测试正文；测试可执行文件独立生成在相应的构建目录中。模块关系见 [系统架构](architecture.md)。

## 依赖准备

先准备 Linux、C11 编译器、GNU Make 和系统 libm/pthread。运行完整测试还需要 Python 3 与 `cryptography`，版本核对方法见 [依赖说明](dependencies.md)。

准备好 Git 后，在本仓库根目录递归初始化 Mbed TLS 3.6.7 及其 framework：

```sh
git submodule update --init --recursive
```

该命令使用仓库固定的提交；不要添加 `--remote` 或更新依赖版本。固定提交和初始化检查见 [依赖说明](dependencies.md)。依赖初始化完成且本地工具齐全后，以下构建和离线测试不需要联网。

如需替换依赖路径，用 `MBEDTLS_DIR` 指定同版本源码的绝对路径，并按依赖说明核对固定提交和 framework。构建命令示例：

```sh
make -C sle-rt -j8 all MBEDTLS_DIR="/ABSOLUTE_PATH/mbedtls-3.6.7"
```

将 `/ABSOLUTE_PATH/mbedtls-3.6.7` 替换为本地 Mbed TLS 3.6.7 源码的绝对路径。后续测试和 ARM 构建使用同一覆盖路径时，也要传入 `MBEDTLS_DIR`；更换依赖路径前先按下文清理构建产物。构建产物写入 `sle-rt/build/` 或 `sle-rt/build-armv7/`，不会写入依赖源码目录。

## 主机构建与测试

依赖齐全后，构建两个 host 程序并执行测试：

```sh
make -C sle-rt -j8 all
make -C sle-rt -j8 test
```

`all`、`host`、`runtime` 均只构建 `sle-rt/build/sle_gnode` 与 `sle-rt/build/sle_tnode`。编译不会连接设备；除 `--help` 等参数处理外，不要在无目标设备的主机运行生产程序。

`test` 执行 16 个 C 测试和 Python 配对 oracle，覆盖帧/链路、校准/调度、模拟 I/O 生命周期、双角色协议、SDU/SSAP、密码学错误路径与 SDK108 默认参数。配对 oracle 使用 Python `cryptography` 独立重算 15 组固定合成向量，使用工程内的合成数据。

交互回归覆盖真实管道输入、EOF 保持连接、Ctrl-C 等信号、未发送输入保留、G 单在途写入/响应超时，以及 T 的队列背压和 MTU 分段。UI 测试在认证边界使用 stub；SSAP/CMTC 编码使用实际实现，配对与密码学由其他独立测试覆盖。设备生命周期测试采用模拟接口，不会打开无线设备。信号清理测试调用实际应用 main 并在 radio 启动后注入信号；它与就绪后的 UI 单元测试分开，未模拟完整加密连接建立后再退出的端到端过程。

可分别执行：

```sh
make -C sle-rt -j8 test-c
make -C sle-rt test-oracles PAIR_PYTHON=python3
make -C sle-rt selftest
```

`selftest` 执行独立的无线核心测试。`sle_gnode --selftest` 只启动同目录的 `test_sle_radio_core`，不把测试正文链接进生产程序；仅执行 `all`/`arm` 不会生成该测试文件，需要先构建相应测试目标。缺少 `cryptography` 时 oracle 会失败；为 `PAIR_PYTHON` 指定已安装该包的解释器后重试。

## ARM 构建与 QEMU

先准备交叉编译器；执行 `test-arm` 还需要 QEMU。将 `ARM_TOOLCHAIN_DIR` 替换为工具链的绝对目录，且确保 `qemu-arm-static` 位于 `PATH`，再执行：

```sh
make -C sle-rt -j8 arm ARM_CC="ARM_TOOLCHAIN_DIR/bin/arm-none-linux-gnueabihf-gcc"
make -C sle-rt -j8 test-arm ARM_CC="ARM_TOOLCHAIN_DIR/bin/arm-none-linux-gnueabihf-gcc" QEMU_ARM=qemu-arm-static
```

ARM 运行产物为 `sle-rt/build-armv7/sle_gnode` 与 `sle-rt/build-armv7/sle_tnode`。默认 Cortex-A9、NEON、hard-float、静态链接；必要时显式指定 `ARM_AR`。`test-arm` 在 QEMU 运行同一组 16 个 C 测试及额外 NEON 解调测试，不重复运行 Python oracle。QEMU 运行时间不能视为目标板性能。

## 清理构建产物

更换 host 编译器或选项前先清理；此操作会删除已有的 host 和 ARM 产物：

```sh
make -C sle-rt clean
```

此命令只删除本工程 `sle-rt/build/` 与 `build-armv7/`。不要与同目录构建并行执行。

## 验证边界

离线测试验证合成数据和模拟接口下的功能，不证明标准符合性、目标板性能或空口互通。默认测试集合未运行上游 Mbed TLS 的全部 self-test。

host 构建与离线测试已通过：两个 host 程序构建成功，16 个 C 测试和 15 组合成配对 oracle 通过。该 host 结果不覆盖 ARM 运行、目标板性能或 WS63 对端准备流程。

构建 ARM 程序后，按 [硬件准备](hardware.md) 确认运行环境，再按 [互通说明](interoperability.md) 检查双向业务。已有实测的覆盖范围见 [验证状态](source-status.md)。
