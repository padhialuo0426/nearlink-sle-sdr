# 构建依赖

本页列出 [E310 构建与离线测试](e310-source.md) 所需的固定依赖版本、初始化方法和工具。依赖源码通过 Git 子模块获取；初始化完成且编译器和测试工具齐全后，可离线构建和测试。

## Mbed TLS 3.6.7 固定子模块

密码学代码从 `deps/mbedtls-3.6.7/` 编译，使用固定版本 **3.6.7**。工程的 gitlink 固定 Mbed TLS 提交，Mbed TLS 内的 gitlink 固定递归依赖 `framework/` 的提交：

| 依赖 | 固定提交 |
| --- | --- |
| Mbed TLS 3.6.7 | `068ff080b369adfac81509f9b57b2afabaf82dc5` |
| Mbed TLS framework | `dde0c4a0e448a0552f18817dcea633bb851fd288` |

[工程 `.gitmodules`](../.gitmodules) 和 [Mbed TLS `.gitmodules`](../deps/mbedtls-3.6.7/.gitmodules) 声明各自的上游来源；[依赖元数据](../deps/dependencies.json) 记录 `git-submodule` 分发类型和固定版本。

准备好 Git 后，在本仓库根目录执行：

```sh
git submodule update --init --recursive
```

该命令检出工程记录的 Mbed TLS 提交及其 framework 递归子模块。首次获取缺失的 Git 对象需要访问上游来源。不要添加 `--remote`，也不要切换到上游分支或其他版本；构建使用上述固定提交。

初始化成功后，两个依赖目录应包含对应源码。

在工程根目录核对本地头文件中的版本：

```sh
grep -E '^#define MBEDTLS_VERSION_STRING[[:space:]]' \
  deps/mbedtls-3.6.7/include/mbedtls/build_info.h
```

预期输出：

```text
#define MBEDTLS_VERSION_STRING         "3.6.7"
```

此检查只确认头文件声明的版本，不证明整份源码与上游逐字节一致。如果文件缺失或版本不同，先核对递归子模块是否初始化成功并检出上述固定提交，再继续构建。

项目通过 [`sle_mbedtls_config.h`](../sle-rt/sle_mbedtls_config.h) 配置所需算法。构建产物写入 `sle-rt/build/` 或 `sle-rt/build-armv7/`，不写入依赖源码目录。上游版权和许可证保留在依赖目录中。

如需复用另一份本地依赖，可通过 `MBEDTLS_DIR` 指定同版本 3.6.7 源码的绝对路径，使用前核对其固定提交与上表一致，并补齐 framework。覆盖方法见 [E310 构建的依赖准备](e310-source.md#依赖准备)。

## 编译器和测试工具

按目标选择工具；只有配对 oracle 需要 Python `cryptography`。oracle 会独立重算合成配对向量，并与预期结果比较。

| 用途 | 所需工具 |
| --- | --- |
| Linux 主机构建与 C 测试 | C11 编译器、GNU Make、libm、pthread |
| Python 配对 oracle | Python 3、`cryptography`；通过 `PAIR_PYTHON` 选择解释器 |
| E310 ARM 构建 | `arm-none-linux-gnueabihf-gcc` 及配套 `ar`；通过 `ARM_CC`、`ARM_AR` 指定 |
| ARM 离线测试 | 上述交叉编译器和 `qemu-arm-static`；通过 `QEMU_ARM` 指定 QEMU |

ARM 默认使用 Cortex-A9、NEON、hard-float 和静态链接。依赖元数据中的 Python 版本描述已测环境，不是完整的传递依赖锁文件。

WS63 对端需要单独准备官方 SDK 和构建工具，见 [WS63 固件准备](ws63-build.md)。准备好本地依赖后，按 [E310 构建文档](e310-source.md) 生成程序并运行离线测试。

## 许可证

项目自写代码采用 [AGPL-3.0-only](../LICENSE)。Mbed TLS 及其 framework 保留上游版权声明和许可文件；各组件的许可范围以对应目录内的声明为准。项目许可证不替代第三方组件的许可证。
