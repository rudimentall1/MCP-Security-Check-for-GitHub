from mcp_security.model.finding import Finding, Severity
from mcp_security.model.report import AttackPath, Decision
from mcp_security.policy import Policy, decide
from mcp_security.scoring.risk import compute_risk_score


def make_finding(severity, rule_id="MSC001"):
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=severity,
        description="d",
        evidence="e",
        file="f",
        remediation="r",
    )


def test_score_is_zero_with_no_findings():
    assert compute_risk_score([], []) == 0


def test_score_sums_severity_weights():
    findings = [make_finding(Severity.HIGH), make_finding(Severity.MEDIUM)]
    assert compute_risk_score(findings, []) == 20 + 10


def test_score_is_capped_at_100():
    findings = [make_finding(Severity.CRITICAL) for _ in range(10)]
    assert compute_risk_score(findings, []) == 100


def test_score_adds_attack_path_bonus():
    attack_path = AttackPath(path_id="AP001", severity=Severity.CRITICAL, chain=["a", "b"], description="d")
    score_without = compute_risk_score([], [])
    score_with = compute_risk_score([], [attack_path])
    assert score_with > score_without
    assert score_with == 25


def test_score_adds_escalation_bonus():
    score_without = compute_risk_score([], [], has_high_risk_escalation=False)
    score_with = compute_risk_score([], [], has_high_risk_escalation=True)
    assert score_with - score_without == 15


def test_score_is_reproducible_for_same_input():
    findings = [make_finding(Severity.HIGH), make_finding(Severity.LOW)]
    assert compute_risk_score(findings, []) == compute_risk_score(findings, [])


def test_decision_block_on_critical_finding():
    policy = Policy()
    findings = [make_finding(Severity.CRITICAL)]
    assert decide(findings, [], policy) == Decision.BLOCK


def test_decision_warn_on_high_finding():
    policy = Policy()
    findings = [make_finding(Severity.HIGH)]
    assert decide(findings, [], policy) == Decision.WARN


def test_decision_allow_when_no_findings_or_paths():
    policy = Policy()
    assert decide([], [], policy) == Decision.ALLOW


def test_decision_block_on_critical_attack_path_even_without_critical_finding():
    policy = Policy()
    attack_path = AttackPath(path_id="AP001", severity=Severity.CRITICAL, chain=["a", "b"], description="d")
    findings = [make_finding(Severity.MEDIUM)]
    assert decide(findings, [attack_path], policy) == Decision.BLOCK


def test_decision_respects_disabled_critical_attack_path_flag():
    policy = Policy(block_on_critical_attack_path=False)
    attack_path = AttackPath(path_id="AP001", severity=Severity.CRITICAL, chain=["a", "b"], description="d")
    findings = [make_finding(Severity.MEDIUM)]
    assert decide(findings, [attack_path], policy) == Decision.WARN


def test_policy_rule_override_ignore_drops_finding():
    policy = Policy(rule_overrides={"MSC001": "ignore"})
    findings = [make_finding(Severity.HIGH, rule_id="MSC001")]
    result = policy.apply_rule_overrides(findings)
    assert result == []


def test_policy_allowlist_suppresses_capability_finding():
    policy = Policy(allowed_capabilities=["network.external"])
    f = make_finding(Severity.HIGH)
    f.capability = "network.external"
    result = policy.apply_allowlist([f])
    assert result == []
