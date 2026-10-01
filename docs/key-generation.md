# 使用运行时密钥与合成测试

运行 `sle_gnode` 或 `sle_tnode` 时，程序会为新的配对生成密钥，无需配置密钥文件。本页说明如何使用这条运行路径、演示公钥编码，以及检查确定性的合成测试向量。构建程序所需的环境见 [E310 构建](e310-source.md)，派生公式与安全边界见 [配对与链路加密](security.md)。

## 让节点生成实际密钥

完成构建与对端准备后，按 [互通运行](interoperability.md)启动所需角色。节点初始化配对上下文时，会执行以下流程：

1. 配置系统随机源。随机回调优先调用 Linux `getrandom()`；仅在返回 `ENOSYS` 时改读初始化阶段已打开的 `/dev/urandom`。初始化无法打开该设备时返回错误，不使用固定测试种子。
2. 在配对的 `prepare()` 阶段，使用 Mbed TLS 3.6.7 的 `secp256r1`（P-256）生成密钥对。连接重建会创建新的配对上下文，不会为每个报文重新生成密钥对。
3. 交换公钥，计算椭圆曲线 Diffie–Hellman（ECDH）共享秘密，再派生 LinkKey 和会话密钥。节点没有从密钥文件导入这些值的接口。

私钥在配对结构中以 32 字节大端形式存储。空口公钥为 64 字节 `X_le32 || Y_le32`，即两个坐标各自按小端序排列，不含 SEC1 非压缩点格式的 `0x04` 前缀。

实现入口为 [G runtime 初始化与随机源](../sle-rt/sle_g_runtime.c)的 `sle_g_runtime_init_variant()`、[T runtime 初始化与随机源](../sle-rt/sle_t_runtime.c)的 `sle_t_runtime_init_variant()`，以及 [G 配对](../sle-rt/sle_pair.c)的 `sle_pair_prepare()` 和 [T 配对](../sle-rt/sle_t_pair.c)的 `sle_t_pair_prepare()`。

## 区分公钥、秘密材料与日志

共享诊断材料前，按用途区分下列数据；“可交换公钥”不意味着其他密钥材料也可公开。

| 材料 | 用途 | 处理方式 |
| --- | --- | --- |
| P-256 公钥 | 空口交换，用于密钥协商 | 可以公开；本工程不要求附带某次连接的公钥 |
| P-256 私钥 | 本端 ECDH 计算 | 保持秘密，由运行时生成 |
| ECDH 共享秘密、LinkKey、会话密钥 | 配对派生和业务加密 | 保持秘密，不作为诊断附件公开 |
| 合成测试用固定私钥及派生值 | 确定性单元测试 | 保留生成来源和“仅测试”标识，不能用于实际连接 |

节点不提供私钥或 LinkKey 的运行时转储接口，但普通业务日志可能包含解密后的应用载荷。公开日志前，检查并移除不宜公开的业务内容。密钥在各阶段的存活时间和擦除限制见 [密钥生命周期](security.md)。

## 演示 P-256 公钥格式

在已安装 Python `cryptography` 的环境中运行下面的代码。它在内存中生成两组演示密钥，打印一方公钥并检查双方 ECDH 结果相同，不保存或打印私钥和共享秘密。

```python
from cryptography.hazmat.primitives.asymmetric import ec

local = ec.generate_private_key(ec.SECP256R1())
peer = ec.generate_private_key(ec.SECP256R1())
public = local.public_key().public_numbers()
public_le = public.x.to_bytes(32, "little") + public.y.to_bytes(32, "little")
assert len(public_le) == 64

shared_local = local.exchange(ec.ECDH(), peer.public_key())
shared_peer = peer.exchange(ec.ECDH(), local.public_key())
assert shared_local == shared_peer
print("public_le:", public_le.hex())
print("P-256 ECDH self-check: PASS")
```

输出的 `public_le` 是 128 个十六进制字符，每次运行通常不同；随后应显示 `P-256 ECDH self-check: PASS`。若导入 `cryptography` 失败，确认所用 Python 解释器已安装该依赖。

该示例只演示公钥编码和 ECDH，不执行 SLE 配对，也不把共享秘密直接当作会话密钥。Python 对象结束生命周期不保证秘密内存已可靠擦除；实际通信仍使用节点的 C 实现。

## 检查合成配对向量

在已具备 Python `cryptography` 的项目根目录中，执行：

```sh
python3 -B tests/gen_pair_vectors.py --check
```

[gen_pair_vectors.py](../tests/gen_pair_vectors.py)使用固定的测试输入，通过 Python cryptography/OpenSSL 生成预期值，并与 [test_sle_pair.c](../tests/test_sle_pair.c)中的常量比较。匹配时输出：

```text
independent Python/OpenSSL oracle: 15 vectors PASS
```

若不匹配，检查生成器与 C 测试中的输入、派生方法及常量是否一致，不要跳过校验。省略 `--check` 会输出合成测试常量；这些固定输入只能用于单元测试，不能替换运行时随机源。校验通过不等于 WS63 空口互通或标准符合性通过。

## 继续构建与验证

根据需要选择后续操作：

- 按 [E310 构建与离线测试](e310-source.md)运行完整测试集合。
- 按 [双角色互通运行](interoperability.md)使用新配对产生的密钥验证实际通信。
- 阅读 [配对与链路加密](security.md)，核对派生公式、计数策略和秘密材料的清理限制。
