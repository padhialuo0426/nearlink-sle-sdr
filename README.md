# nearlink-sle-sdr

ANTSDR E310（v1）用户态 SLE 实现，用于与海思 WS63 官方 SDK **1.10.108** 的 UART 示例进行配对和加密双向通信。

WS63 对端使用官方 UART 示例；server 需增加 WRITE 声明。Mbed TLS **3.6.7** 通过固定提交的 Git 子模块提供；构建前按 [依赖准备](docs/dependencies.md) 递归初始化。

提供两个运行程序：`sle_gnode` 连接 WS63 server，`sle_tnode` 接受 WS63 client 连接。两者均支持 `--interactive 1` 双向终端交互。源码范围和验证限制见 [当前状态](docs/source-status.md)。

- [构建与测试](docs/e310-source.md)
- [互通运行方法](docs/interoperability.md)
- [WS63 固件准备](docs/ws63-build.md)
- [依赖准备](docs/dependencies.md)
- [完整文档索引](docs/README.md)

项目自写代码采用 [GNU Affero General Public License v3.0（AGPL-3.0-only）](LICENSE)。第三方组件保留各自的版权声明和许可证。
