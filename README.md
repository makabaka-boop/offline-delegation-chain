# delegauth

离线 Ed25519 委任令牌命令行验证器。程序只读取 JSON 输入，不连接身份服务。

## 输入

```bash
go run . request.json
# 或
cat request.json | go run . -
```

JSON 字段：

- `root_public_keys`：1～4 个标准 base64 编码的 Ed25519 信任根公钥。
- `tokens`：最多 40 个已签名委任令牌。
- `revoked_token_ids`：已撤销令牌 ID；其中任何 ID 都不能出现在返回链中。
- `query`：`principal`、`action`、`resource` 和整数 `time`。

子令牌动作必须是父令牌动作集合的子集；资源前缀必须相等，或按路径段收窄；半开有效期为 `not_before <= time < not_after`；子令牌剩余委任层数必须严格小于父令牌。

## 签名载荷

所有签名字段使用大端长度前缀编码：

1. `id`：`uint32` 长度 + UTF-8 字节；
2. `issuer`：`uint32` 长度 + 32 字节 Ed25519 公钥；
3. `subject`：同上；
4. 动作：`uint32` 动作数量，随后每个动作以长度前缀字符串编码；动作按字典序规范化；
5. `resource_prefix`：长度前缀字符串；
6. `not_before`、`not_after`：大端 `int64`；
7. `remaining_delegations`：大端 `uint32`。

签名为标准 Ed25519 签名，JSON 中以标准 base64 表示。载荷包含 `id`，可把撤销 ID 绑定到对应令牌，防止仅替换未签名 ID 来逃避撤销。

## 路径段匹配

- `/a/b` 匹配 `/a/b` 和 `/a/b/c`；
- `/a/b` 不匹配 `/a/b2`、`/a/bb` 或 `/ab`；
- `/` 是绝对路径的根前缀。

## 输出与退出码

成功授权返回退出码 `0`、`"authorized": true`、字典序最小的 `token_ids`，以及每层的动作、路径、时间和委任层数收窄证据。无有效链或整批无效时退出码 `1`。JSON 无法解析等输入错误退出码 `2`。

运行测试：

```bash
go test -v ./...
```
