灰度开关只对内部租户打开，结果外部租户按百分比也被放了进来：分桶用随机数，同一租户每次结果不同；分桶把租户与开关名顺序调换，不同开关相关性过高；租户白名单用前缀比较，内部租户前缀被外部命中；百分比放量不看租户白名单，外部租户被放进来；规则按声明顺序而不是优先级求值，后面的规则覆盖前面；命中规则后继续求值，最终结果取最后一条；覆盖写入不校验调用者角色，任意用户可改；覆盖记录不带审计字段，无法追责；策略校验不检查百分比是否有租户限制；批量求值复用上下文，后一个请求带上一个请求的租户。flag/gate.py 是核心，tests/test_gate.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式

在仓库根目录执行 python -m pytest tests -q。初始状态必须恰好是 15 failed，并且不能出现 collection、import 或 syntax error；8 个函数全部 raise NotImplementedError，因此 15 个用例都会在进入断言前直接失败。把 src/flag/gate.py 按 docstring 契约实现后，应当变成 15 passed，不允许修改 tests。

字段表

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言/框架：Python 3, pytest
环境可复现等级：无外部依赖

约束

tests 目录不可修改：不得增删用例、不得改断言、不得跳过，只能改 src/flag/gate.py。本仓库采用 src 布局，实现包位于 src/flag，导入路径由 pyproject.toml 里的 pytest pythonpath 配置指定为 src，不使用 conftest.py，也不需要先执行安装。实现只允许使用标准库 hashlib、math、json 与 pytest，离线、无随机、不联网。
## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

