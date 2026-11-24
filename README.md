客户端给服务端做了证书固定，换证书那天没更新固定集，结果还能连上假冒的服务端：摘要只哈希公钥，证书其余字段完全不参与；解析固定集时丢掉备份 pin，只留下主 pin；判断生效期只看起始时间，越过结束时间仍算有效；匹配固定项时不看生效期，过期 pin 继续放行；备份 pin 被当成永久有效，直接跳过生效期；链绑定只检查 pin 非空，不在链上的 pin 也接受；回退前不检查固定集是否允许回退，直接静默退回链校验；回退成功不写审计记录，事后无法追溯；校验固定集不检查备份 pin 是否存在；批量校验复用第一张证书的摘要，后续连接沿用前一个 pin。engine/pin/verify.py 是核心，tests/pin/test_verify.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```powershell
cd D:\gsb-20261119\sec-tls-pinning
python -m pytest tests -q
```

初始状态必须恰好为：

```text
15 failed
```

15 个失败必须全部由 `engine/pin/verify.py` 中的 `raise NotImplementedError` 桩触发，不允许出现 collection error、import error、syntax error、skip 或 xfail。修复后应为 `15 passed`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 目录与 engine 嵌套布局

```text
sec-tls-pinning/
  README.md
  conftest.py
  engine/__init__.py
  engine/pin/__init__.py
  engine/pin/verify.py
  tests/pin/test_verify.py
```

仓库根目录是 `sec-tls-pinning/`，Python 包根是 `engine/`，二级子包是 `engine/pin/`，所以唯一实现文件的导入路径是 `engine.pin.verify`。不要把它改成扁平的 `pin/verify.py`，也不要让测试从仓库根直接导入 `verify`。`conftest.py` 只负责把仓库根加入 `sys.path`。

## 数据契约

固定集文本是 JSON 对象，字段如下：

```json
{
  "primary": ["sha256:..."],
  "backup": ["sha256:..."],
  "not_before": "2026-01-01T00:00:00Z",
  "not_after": "2027-01-01T00:00:00Z",
  "allow_fallback": true
}
```

`parse_pin_set` 返回：

```python
{
    "primary": [
        {"pin": "sha256:...", "not_before": datetime, "not_after": datetime}
    ],
    "backup": [
        {"pin": "sha256:...", "not_before": datetime, "not_after": datetime}
    ],
    "allow_fallback": True,
}
```

缺失的生效期保留为 `None`，交给 `validate_pin_set` 报告，不要静默补成永久有效。生效期两端都含；时间必须是带时区的 `datetime`。

证书使用字典表示，完整证书字节放在 `der`，公钥字节放在 `public_key`。固定值格式固定为 `sha256:` 加小写十六进制摘要，摘要覆盖完整 `der`，不是只覆盖 `public_key`。

`check_fallback` 没有 `now` 参数，调用方必须通过 `policy` 传入求值时间和审计落点：

```python
policy = {"now": datetime(..., tzinfo=timezone.utc), "audit": []}
```

回退成功时，`check_fallback` 必须向 `policy["audit"]` 追加一条 `{"event": "pin_fallback", "pin": "..."}`；未允许回退、备份已过期、备份不在链上或只有链校验可用时，必须返回 `False` 且不得写记录。`pin_batch` 的 `now` 参数对每条连接生效，不得复用上一条连接的摘要、pin 或回退结果。

`validate_pin_set` 的问题码固定为 `missing_backup`、`missing_validity`、`fallback_to_chain`，返回顺序也按此顺序。`fallback_to_chain` 表示允许回退但没有任何备份 pin，实际只剩链校验可退。

`pin_batch` 每条连接返回：

```python
{
    "peer-id": {"accepted": True, "pin": "sha256:...", "fallback": False}
}
```

## 约束

- `tests/pin/test_verify.py` 是不可修改的验收契约，不得改测试、加 skip/xfail、放宽断言或 monkeypatch 桩函数。
- 只修改 `engine/pin/verify.py`，该文件恰好包含 8 个待修函数；修复时保留函数名、参数和返回类型。
- 只能使用 Python 标准库和 pytest，不联网，不引入第三方依赖，不读取系统时钟；所有时间由调用方传入。
- 不允许把“未知 pin”降级为“证书链校验通过即可”。没有仍生效且绑定到链上的备份 pin 时，必须失败关闭。