# 实现参考与资料来源

本页按问题列出本工程的源码、测试和必要的官方背景，供阅读 [架构](architecture.md)、[协议栈](protocol-stack.md)、[物理层](physical-layer.md) 和 [安全实现](security.md) 时查阅。实现细节以相对源码链接和函数名定位；外部资料用于补充概念或准备对端。

## 从问题定位源码和测试

下表列出主要入口。函数的输入、状态转换和错误处理以链接中的实现为准。

| 问题 | 文档入口 | 主要实现 / 验证入口 |
| --- | --- | --- |
| 两个节点进程如何连接硬件 | [架构](architecture.md) | [sle_radio.c](../sle-rt/sle_radio.c)、[sle_iio.c](../sle-rt/sle_iio.c) |
| IQ 如何变成帧、帧如何变成 IQ | [物理层](physical-layer.md) | [sle_phy.c](../sle-rt/sle_phy.c)、[sle_demod.c](../sle-rt/sle_demod.c)、[sle_gfsk.c](../sle-rt/sle_gfsk.c) |
| 广播接入与事件调度 | [协议栈](protocol-stack.md) | [sle_access.c](../sle-rt/sle_access.c)、[sle_clock.c](../sle-rt/sle_clock.c)、[test_sle_access.c](../tests/test_sle_access.c) |
| 链路重传与重复过滤 | [协议栈](protocol-stack.md) | [sle_link.c](../sle-rt/sle_link.c)、[test_sle_link.c](../tests/test_sle_link.c) |
| 密钥如何生成与使用 | [安全](security.md)、[密钥生成](key-generation.md) | [sle_crypto.c](../sle-rt/sle_crypto.c)、[sle_pair.c](../sle-rt/sle_pair.c)、[sle_t_pair.c](../sle-rt/sle_t_pair.c) |
| MIC、计数器与状态转换 | [安全](security.md) | [test_sle_pair.c](../tests/test_sle_pair.c)、[test_sle_g_runtime.c](../tests/test_sle_g_runtime.c)、[test_sle_t_protocol.c](../tests/test_sle_t_protocol.c) |
| 能力交换、分片与属性写入 | [协议栈](protocol-stack.md) | [sle_cmtc.c](../sle-rt/sle_cmtc.c)、[sle_sdu.c](../sle-rt/sle_sdu.c)、[sle_ssap_server.c](../sle-rt/sle_ssap_server.c) |
| 节点完成哪些业务 | [互通运行](interoperability.md) | [sle_gnode.c](../sle-rt/sle_gnode.c)、[sle_tnode.c](../sle-rt/sle_tnode.c)、[功能验证](validation-results.md) |
| 如何构建及判断测试范围 | [E310 构建](e310-source.md)、[实现与验证范围](source-status.md) | [Makefile](../sle-rt/Makefile)、[tests/](../tests/) |

## 官方背景与依赖版本

这些资料说明通用概念、对端开发接口或基础算法。它们所列的完整能力不等于本工程的实现范围。

<a id="r1"></a>
### R1：星闪联盟安全白皮书

星闪联盟《星闪无线短距通信技术（SparkLink 1.0）安全白皮书 — 网络安全》提供系统分层、SLB / SLE 区分和 G / T 角色的概念背景，可从[联盟下载入口](https://old-page.sparklink.org.cn/news_download.php?id=638)获取。该资料适用于其注明的 SparkLink 1.0；本工程的派生公式、字段与安全边界见 [安全实现](security.md)。

<a id="r2"></a>
### R2：海思 WS63 软件开发指南

[WS63 官方文档](https://docs.hisilicon.com/projects/fbb_ws63/master/)与[软件开发指南](https://docs.hisilicon.com/repos/fbb_ws63/zh-CN/master/software/软件开发指南/软件开发指南.html)介绍对端 SDK 的 API 分层。与本工程相关的是“BLE&SLE 软件开发 → 星闪开发流程”中的 Device Discovery、Connection Manager、SSAP server / client。

`master` 页面会变化，不能代替指定 SDK 版本。示例选择及 server WRITE 修改以 [WS63 对端准备](ws63-build.md)为准。

<a id="r3"></a>
### R3：WS63 SDK 1.10.108

对端采用 [HiSpark/fbb_ws63 官方 SDK](https://gitcode.com/HiSpark/fbb_ws63) **1.10.108**，对应提交 `424dc5571fb761dfa7ed5969282a982f7a5ed71f`。SDK 不随本工程分发，准备要求见 [依赖说明](dependencies.md)和 [WS63 对端准备](ws63-build.md)。

<a id="r4"></a>
### R4：Mbed TLS 3.6.7

E310 密码学依赖 [Mbed TLS 官方源码](https://github.com/Mbed-TLS/mbedtls) **3.6.7**，源码位于 `deps/mbedtls-3.6.7/`。依赖准备方式见 [依赖说明](dependencies.md)。

[sle_mbedtls_config.h](../sle-rt/sle_mbedtls_config.h) 配置所需算法，[sle_crypto.c](../sle-rt/sle_crypto.c) 封装 AES、CMAC、CCM 与 P-256 运算；实际编译单元见 [Makefile](../sle-rt/Makefile)。库的算法实现与本项目的协议集成是两个验证层次，版本号本身不代表安全审计结果。

## 如何理解验证结论

不同材料能回答不同问题。源码、离线测试与实机结果需要结合使用。

| 材料 | 能说明什么 | 不能据此说明什么 |
| --- | --- | --- |
| 联盟白皮书 | 通用架构与安全目标 | 本工程具备其中全部能力 |
| 厂商开发指南 | WS63 API 职责与使用方法 | 本工程的空口字节布局必然正确 |
| 本工程源码 | 字段、算法、状态转换和错误处理 | 所有分支已经上板或符合完整标准 |
| 离线测试 | 给定输入与断言覆盖的行为 | 射频时序、长期稳定性或安全审计结论 |
| 指定二进制的实机验证 | 对应对端与条件下的功能观察 | 对所有设备、版本、负载和环境的一般保证 |

具体覆盖见 [源码范围与验证状态](source-status.md)和[双角色功能验证](validation-results.md)。测试使用的固定密码材料由 [合成向量生成器](../tests/gen_pair_vectors.py)定义，实际运行的密钥生成方式见 [密钥生成](key-generation.md)。

文档可离线阅读。源码链接附有函数名时，可直接在文件中定位；Mermaid 图不能渲染时，可结合图源码与相邻说明阅读。外部资料是补充阅读入口，工具链、SDK 和源码依赖的准备要求由 [依赖说明](dependencies.md)统一说明。
