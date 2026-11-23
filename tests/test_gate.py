"""灰度开关求值的行为契约测试（恰好 15 个，初始全红）。

前 10 个用例分别对应题面中的 10 个缺陷，后 5 个是基础回归与一致性用例。
所有输入都是显式构造的，不使用随机数、不联网、不读取真实时钟；字符串与属性
比较使用零容差。tests 目录不可修改。
"""

import pytest

from flag.gate import (
    bucket_of,
    evaluate,
    flag_batch,
    override_for,
    percentage_rollout,
    rule_matches,
    tenant_scope_ok,
    validate_policy,
)


def test_defect_01_bucket_is_deterministic_not_random():
    """缺陷 1：分桶不能用随机数，同一租户每次结果必须相同。"""
    tenant = "acme"
    flag = "checkout-ui"

    first = bucket_of(tenant, flag)
    assert 0 <= first <= 99

    other = bucket_of("globex", flag)
    assert bucket_of(tenant, flag) == first
    assert bucket_of("globex", flag) == other

    for _ in range(20):
        assert bucket_of(tenant, flag) == first


def test_defect_02_bucket_combines_tenant_and_flag():
    """缺陷 2：分桶必须同时看租户与开关名，不能对同一租户的所有开关复用同一个桶。"""
    flags = [
        "checkout-ui",
        "search-v2",
        "pricing",
        "onboarding",
        "billing",
        "export",
        "alerts",
        "admin-console",
        "mobile-home",
        "desktop-nav",
    ]

    buckets = [bucket_of("acme", flag) for flag in flags]

    assert all(0 <= bucket <= 99 for bucket in buckets)
    assert len(set(buckets)) >= 5
    assert len(set(buckets)) > 1


def test_defect_03_whitelist_uses_exact_match():
    """缺陷 3：租户白名单必须完全相等匹配，不能用前缀比较放过外部租户。"""
    policy = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["internal-corp", "acme"],
        "default_variant": "off",
        "rules": [],
        "overrides": [],
    }

    assert tenant_scope_ok({"tenant": "internal-corp", "attrs": {}}, policy) is True
    assert tenant_scope_ok({"tenant": "acme", "attrs": {}}, policy) is True
    assert tenant_scope_ok({"tenant": "internal-corp-evil", "attrs": {}}, policy) is False
    assert tenant_scope_ok({"tenant": "internal", "attrs": {}}, policy) is False
    assert tenant_scope_ok({"tenant": "INTERNAL-CORP", "attrs": {}}, policy) is False


def test_defect_04_percentage_does_not_bypass_whitelist():
    """缺陷 4：百分比放量必须先过租户白名单，外部租户不能被百分比放进来。"""
    policy = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["acme"],
        "default_variant": "off",
        "overrides": [],
        "rules": [
            {
                "id": "r-open",
                "priority": 10,
                "flag": "checkout-ui",
                "tenants": [],
                "attrs": {},
                "percent": 100,
                "variant": "on",
            }
        ],
    }

    external = evaluate(
        "checkout-ui",
        {"request_id": "req-evil", "tenant": "evil", "attrs": {}},
        policy,
    )
    assert external == {"variant": "off", "matched_rule": None, "allowed": False}

    internal = evaluate(
        "checkout-ui",
        {"request_id": "req-acme", "tenant": "acme", "attrs": {}},
        policy,
    )
    assert internal == {"variant": "on", "matched_rule": "r-open", "allowed": True}


def test_defect_05_rules_follow_priority_not_declaration_order():
    """缺陷 5：规则按优先级求值，后面的低优先级规则不能覆盖前面的高优先级规则。"""
    context = {"request_id": "req-1", "tenant": "acme", "attrs": {"region": "cn"}}
    high = {
        "id": "r-high",
        "priority": 9,
        "flag": "checkout-ui",
        "tenants": ["acme"],
        "attrs": {"region": "cn"},
        "percent": 100,
        "variant": "on",
    }
    low = {
        "id": "r-low",
        "priority": 1,
        "flag": "checkout-ui",
        "tenants": ["acme"],
        "attrs": {"region": "cn"},
        "percent": 100,
        "variant": "off",
    }
    policy = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["acme"],
        "default_variant": "off",
        "overrides": [],
        "rules": [high, low],
    }

    assert rule_matches(high, context) is True
    assert rule_matches(low, context) is True

    result = evaluate("checkout-ui", context, policy)
    assert result["matched_rule"] == "r-high"
    assert result["variant"] == "on"
    assert result["allowed"] is True


def test_defect_06_evaluation_stops_at_first_priority_hit():
    """缺陷 6：命中优先级最高的规则后立即停止，不能继续求值并取最后一条。"""
    context = {"request_id": "req-1", "tenant": "acme", "attrs": {"region": "cn"}}
    rules = [
        {
            "id": "r-top",
            "priority": 9,
            "flag": "checkout-ui",
            "tenants": ["acme"],
            "attrs": {"region": "cn"},
            "percent": 100,
            "variant": "top",
        },
        {
            "id": "r-mid",
            "priority": 5,
            "flag": "checkout-ui",
            "tenants": ["acme"],
            "attrs": {"region": "cn"},
            "percent": 100,
            "variant": "mid",
        },
        {
            "id": "r-last",
            "priority": 1,
            "flag": "checkout-ui",
            "tenants": ["acme"],
            "attrs": {"region": "cn"},
            "percent": 100,
            "variant": "last",
        },
    ]
    policy = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["acme"],
        "default_variant": "off",
        "overrides": [],
        "rules": rules,
    }

    result = evaluate("checkout-ui", context, policy)
    assert result == {"variant": "top", "matched_rule": "r-top", "allowed": True}


def test_defect_07_non_admin_override_is_rejected():
    """缺陷 7：覆盖写入必须校验调用者角色，普通用户不能改覆盖。"""
    overrides = [
        {
            "tenant": "acme",
            "flag": "checkout-ui",
            "variant": "on",
            "actor_role": "viewer",
            "audit": {
                "actor": "user-1",
                "at": "2026-01-01T00:00:00Z",
                "reason": "self service",
            },
        }
    ]

    with pytest.raises(PermissionError):
        override_for("acme", "checkout-ui", overrides)


def test_defect_08_override_requires_audit():
    """缺陷 8：覆盖记录必须带完整审计字段，否则无法追责。"""
    without_audit = [
        {
            "tenant": "acme",
            "flag": "checkout-ui",
            "variant": "on",
            "actor_role": "admin",
        }
    ]
    incomplete_audit = [
        {
            "tenant": "acme",
            "flag": "checkout-ui",
            "variant": "on",
            "actor_role": "admin",
            "audit": {"actor": "ops-1", "at": "2026-01-01T00:00:00Z"},
        }
    ]

    with pytest.raises(ValueError):
        override_for("acme", "checkout-ui", without_audit)
    with pytest.raises(ValueError):
        override_for("acme", "checkout-ui", incomplete_audit)


def test_defect_09_validate_flags_percent_without_tenant_scope():
    """缺陷 9：策略校验必须发现非全量百分比却没有租户限制的规则。"""
    unscoped = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["acme"],
        "default_variant": "off",
        "rules": [
            {
                "id": "r-half",
                "priority": 5,
                "flag": "checkout-ui",
                "tenants": [],
                "percent": 30,
                "variant": "on",
            }
        ],
    }
    scoped = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["acme"],
        "default_variant": "off",
        "rules": [
            {
                "id": "r-half",
                "priority": 5,
                "flag": "checkout-ui",
                "tenants": ["acme"],
                "percent": 30,
                "variant": "on",
            }
        ],
    }

    issues = validate_policy(unscoped)
    assert "percent_without_tenant_restriction" in issues
    assert "percent_without_tenant_restriction" not in validate_policy(scoped)
    assert validate_policy(scoped) == []


def test_defect_10_batch_keeps_contexts_isolated():
    """缺陷 10：批量求值必须逐个上下文独立，后一个请求不能继承前一个请求的租户。"""
    policy = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["acme"],
        "default_variant": "off",
        "overrides": [],
        "rules": [
            {
                "id": "r-acme",
                "priority": 5,
                "flag": "checkout-ui",
                "tenants": ["acme"],
                "attrs": {},
                "percent": 100,
                "variant": "on",
            }
        ],
    }
    contexts = [
        {"request_id": "req-1", "tenant": "acme", "attrs": {}},
        {"request_id": "req-2", "tenant": "evil", "attrs": {}},
    ]

    results = flag_batch(contexts, policy)

    assert results["req-1"] == {
        "variant": "on",
        "matched_rule": "r-acme",
        "allowed": True,
    }
    assert results["req-2"] == {
        "variant": "off",
        "matched_rule": None,
        "allowed": False,
    }
    assert contexts == [
        {"request_id": "req-1", "tenant": "acme", "attrs": {}},
        {"request_id": "req-2", "tenant": "evil", "attrs": {}},
    ]


def test_extra_01_same_tenant_bucket_is_stable():
    """额外用例：同一租户在同一开关上的分桶与放量结果稳定。"""
    flag = "checkout-ui"
    first = bucket_of("acme", flag)

    for _ in range(50):
        assert bucket_of("acme", flag) == first
    assert 0 <= first <= 99

    assert percentage_rollout("acme", 100) is True
    assert percentage_rollout("acme", 0) is False

    rollout = percentage_rollout("acme", 50)
    assert rollout == (bucket_of("acme", "rollout") < 50)
    for _ in range(5):
        assert percentage_rollout("acme", 50) == rollout


def test_extra_02_buckets_differ_across_flags():
    """额外用例：同一租户在不同开关上的分桶彼此独立，不能全部落在同一个桶。"""
    flags = ["flag-" + str(index) for index in range(20)]
    buckets = [bucket_of("acme", flag) for flag in flags]

    assert len(set(buckets)) >= 8
    assert len(set(buckets)) > 1
    assert min(buckets) >= 0
    assert max(buckets) <= 99


def test_extra_03_external_tenant_is_rejected():
    """额外用例：不在白名单里的租户被拒绝，不能靠百分比规则进入。"""
    policy = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["acme"],
        "default_variant": "off",
        "overrides": [],
        "rules": [
            {
                "id": "r-open",
                "priority": 10,
                "flag": "checkout-ui",
                "tenants": [],
                "attrs": {},
                "percent": 100,
                "variant": "on",
            }
        ],
    }

    assert tenant_scope_ok({"tenant": "globex", "attrs": {}}, policy) is False
    assert tenant_scope_ok({"tenant": "acme", "attrs": {}}, policy) is True

    result = evaluate(
        "checkout-ui",
        {"request_id": "req-1", "tenant": "globex", "attrs": {}},
        policy,
    )
    assert result == {"variant": "off", "matched_rule": None, "allowed": False}


def test_extra_04_override_rules_require_admin():
    """额外用例：管理员覆盖可读取，非管理员覆盖被拒绝，其余租户无覆盖。"""
    good = {
        "tenant": "acme",
        "flag": "checkout-ui",
        "variant": "on",
        "actor_role": "admin",
        "audit": {
            "actor": "ops-1",
            "at": "2026-01-01T00:00:00Z",
            "reason": "manual unlock",
        },
    }

    record = override_for("acme", "checkout-ui", [good])
    assert record["tenant"] == "acme"
    assert record["variant"] == "on"
    assert override_for("globex", "checkout-ui", [good]) == {}
    assert override_for("acme", "another-flag", [good]) == {}

    with pytest.raises(PermissionError):
        override_for("acme", "checkout-ui", [{**good, "actor_role": "user"}])


def test_extra_05_batch_matches_single_evaluation():
    """额外用例：两批独立批量求值互不影响，且与逐个单独求值完全相同。"""
    policy = {
        "flag": "checkout-ui",
        "tenant_whitelist": ["acme"],
        "default_variant": "off",
        "overrides": [],
        "rules": [
            {
                "id": "r-cn",
                "priority": 5,
                "flag": "checkout-ui",
                "tenants": ["acme"],
                "attrs": {"region": "cn"},
                "percent": 100,
                "variant": "on",
            }
        ],
    }
    contexts = [
        {"request_id": "req-cn", "tenant": "acme", "attrs": {"region": "cn"}},
        {"request_id": "req-us", "tenant": "acme", "attrs": {"region": "us"}},
    ]

    batch = flag_batch(contexts, policy)
    assert batch["req-cn"] == {
        "variant": "on",
        "matched_rule": "r-cn",
        "allowed": True,
    }
    assert batch["req-us"] == {
        "variant": "off",
        "matched_rule": None,
        "allowed": True,
    }
    assert batch["req-cn"] == evaluate("checkout-ui", contexts[0], policy)
    assert batch["req-us"] == evaluate("checkout-ui", contexts[1], policy)

    second = flag_batch(contexts, policy)
    assert second == batch
