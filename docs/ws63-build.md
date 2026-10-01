# 准备 WS63 官方 UART 示例

为 E310 程序准备 WS63 官方 SDK **1.10.108** 的 UART 对端。`sle_tnode` 对应官方 client；`sle_gnode` 对应增加 WRITE 声明的官方 server。角色运行方法见 [双角色互通](interoperability.md)。此对端准备流程尚未完成端到端复现验证。

本工程不包含 WS63 SDK、固件或构建工具。以下步骤以已准备好的官方 SDK 和工具为前提。

## 准备 SDK 与示例

使用 HiSpark `fbb_ws63` **1.10.108**、已安装的 **hs-fbb-cli 1.2.1**、**HCC 7.3.0** 及 FBB 所需依赖。所有修改和构建都在自己的 SDK 工作副本中完成。

1. 以官方工程的 `src/` 作为 SDK 构建根目录。
2. 将官方 `vendor/BearPi-Pico_H3863/products/` 复制到 SDK 工作副本的 `application/samples/products/`，保留其 Kconfig、CMake 和许可证。
3. 确认使用的是上述 products UART 示例。同一 SDK 中的 `application/samples/bt/sle/sle_uart/` 是另一套示例，不适用本页的路径和配置说明。

## 为 server 增加 WRITE 声明

E310 G 程序需要向 server 属性写入数据。在 SDK 工作副本中编辑以下文件：

```text
application/samples/products/sle_uart/sle_uart_server/sle_uart_server.c
```

定位 `sle_uuid_server_property_add()`，将属性操作声明：

```c
property.operate_indication = SSAP_OPERATE_INDICATION_BIT_READ | SSAP_OPERATE_INDICATION_BIT_NOTIFY;
```

改为：

```c
property.operate_indication = SSAP_OPERATE_INDICATION_BIT_READ | SSAP_OPERATE_INDICATION_BIT_WRITE |
                             SSAP_OPERATE_INDICATION_BIT_NOTIFY;
```

只在 `property.operate_indication` 上增加 `SSAP_OPERATE_INDICATION_BIT_WRITE`。同一函数中的 `descriptor.operate_indication` 已含 WRITE，不是修改目标；`property.permissions` 和 `SLE_UUID_TEST_PROPERTIES` 无需修改。

该固件应标为“官方 UART server 加 WRITE 声明”。client 业务源码保持官方原样。SDK 仍使用厂商提供的预编译协议库，此修改不涉及重建协议库。

## 配置角色与构建

先让 FBB 指向自己的 SDK 工作副本和已准备好的工具目录，再在 SDK 构建根目录操作。下面的 `FBB_PATH` 是 FBB 可执行文件的绝对路径占位符；`menuconfig` 需要终端或 PTY。

```sh
"FBB_PATH" doctor
"FBB_PATH" menuconfig ws63-liteos-app
```

仅在 `doctor` 成功后进入配置。启用 **Application** 下的 **products** 和 **SLE UART**，关闭其他示例，选择所需角色及 **normal** 模式：

| E310 程序 | WS63 角色 | 必需修改 |
| --- | --- | --- |
| `sle_gnode` | server | 增加上述 WRITE 声明 |
| `sle_tnode` | client | 无业务源码修改 |

两角色使用 UART0、TX GPIO17、RX GPIO18。必须显式选择角色；官方 client 停止扫描后会连接并配对，不能作为只扫描程序使用。

保存后检查 `build/config/target_config/ws63/menuconfig/acore/ws63_liteos_app.config`。共同配置如下：

```text
CONFIG_SAMPLE_ENABLE=y
CONFIG_ENABLE_PRODUCTS_SAMPLE=y
CONFIG_SAMPLE_SUPPORT_SLE_UART=y
CONFIG_SAMPLE_SUPPORT_NORMAL_TYPE=y
CONFIG_SLE_UART_BUS=0
CONFIG_UART_TXD_PIN=17
CONFIG_UART_RXD_PIN=18
```

client 需启用 `CONFIG_SAMPLE_SUPPORT_SLE_UART_CLIENT` 和 `CONFIG_SUPPORT_SLE_CENTRAL`；server 需启用 `CONFIG_SAMPLE_SUPPORT_SLE_UART_SERVER` 和 `CONFIG_SUPPORT_SLE_PERIPHERAL`。关闭另一角色及其 central/peripheral 配置，同时关闭低延迟和 performance 模式。

确认配置后干净构建；每次切换角色都重新配置并干净构建：

```sh
CCACHE_DISABLE=1 "FBB_PATH" build --clean -j 8 --json-summary ws63-liteos-app
```

检查 `output/ws63/acore/ws63-liteos-app/mconfig.h` 和编译日志，确认编入 `application/samples/products/sle_uart/` 下所选角色的源码。应用产物位于 `output/ws63/acore/ws63-liteos-app/`，完整包位于 `output/ws63/fwpkg/ws63-liteos-app/ws63-liteos-app_all.fwpkg`。切换角色前保存所需产物，避免下一次构建替换它们。

准备好对端固件后，按 [硬件说明](hardware.md) 核对设备与接线，再按 [互通说明](interoperability.md) 检查双向加密业务。SDK 构建成功本身不能证明空口互通。
