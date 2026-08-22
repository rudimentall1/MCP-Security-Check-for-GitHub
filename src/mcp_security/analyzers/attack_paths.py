"""Attack path detection.

Evaluates *combinations* of capabilities present on a component (not just
individual capabilities) and reports realistic attack chains. This is
distinct from single-capability rules: a component can be "safe" per
individual rules yet still expose a dangerous combination.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Set

from mcp_security.model.finding import Severity
from mcp_security.model.report import AttackPath

# Each attack path definition: the set of capability ids that must all be
# present (on the same component) for the chain to fire, an ordered chain
# for display purposes, severity, and a human explanation.


@dataclass(frozen=True)
class AttackPathDefinition:
    path_id: str
    required: frozenset
    chain: tuple
    severity: Severity
    description: str
    remediation: str


ATTACK_PATH_DEFINITIONS: List[AttackPathDefinition] = [
    AttackPathDefinition(
        path_id="AP001",
        required=frozenset({"secrets.read", "network.external"}),
        chain=("secrets.read", "network.external"),
        severity=Severity.CRITICAL,
        description="Potential secret/data exfiltration path: the component can read secrets and also reach external networks.",
        remediation="Restrict network access to required endpoints only, or remove secret access if not strictly needed.",
    ),
    AttackPathDefinition(
        path_id="AP002",
        required=frozenset({"filesystem.read", "network.external"}),
        chain=("filesystem.read", "network.external"),
        severity=Severity.HIGH,
        description="Potential local data exfiltration path: the component can read local files and also reach external networks.",
        remediation="Scope filesystem access to the minimum required directory, or restrict network egress.",
    ),
    AttackPathDefinition(
        path_id="AP003",
        required=frozenset({"filesystem.write", "shell.execute"}),
        chain=("filesystem.write", "shell.execute"),
        severity=Severity.CRITICAL,
        description="Potential code/config tampering path: the component can write files and execute shell commands, enabling self-modifying or persistence behavior.",
        remediation="Avoid combining shell execution with unrestricted filesystem write; sandbox or split responsibilities across components.",
    ),
    AttackPathDefinition(
        path_id="AP004",
        required=frozenset({"shell.execute", "network.external"}),
        chain=("shell.execute", "network.external"),
        severity=Severity.CRITICAL,
        description="Potential remote payload execution/exfiltration path: the component can execute shell commands and reach external networks.",
        remediation="Remove shell execution capability if not required, or restrict network egress to a strict allowlist.",
    ),
    AttackPathDefinition(
        path_id="AP005",
        required=frozenset({"package.install", "package.execute"}),
        chain=("package.install", "package.execute"),
        severity=Severity.HIGH,
        description="Potential supply-chain execution path: the component can install and then execute packages, enabling arbitrary third-party code execution.",
        remediation="Pin dependency versions and verify package sources before allowing install+execute in the same component.",
    ),
    AttackPathDefinition(
        path_id="AP006",
        required=frozenset({"credentials.read", "network.external"}),
        chain=("credentials.read", "network.external"),
        severity=Severity.CRITICAL,
        description="Potential credential exfiltration path: the component can read credential material and also reach external networks.",
        remediation="Remove credential access if not required, or isolate the component from external network egress.",
    ),
    AttackPathDefinition(
        path_id="AP007",
        required=frozenset({"filesystem.write", "network.external", "shell.execute"}),
        chain=("filesystem.write", "shell.execute", "network.external"),
        severity=Severity.CRITICAL,
        description="Critical multi-step attack path: the component can write files, execute shell commands, and reach external networks -- sufficient primitives for a full compromise chain.",
        remediation="Treat this combination as a hard blocker; require explicit security review before allowing all three capabilities together.",
    ),
]


def detect_attack_paths(capability_ids: Set[str]) -> List[AttackPath]:
    """Return attack paths whose required capability set is a subset of ``capability_ids``."""
    results: List[AttackPath] = []
    for definition in ATTACK_PATH_DEFINITIONS:
        if definition.required.issubset(capability_ids):
            results.append(
                AttackPath(
                    path_id=definition.path_id,
                    severity=definition.severity,
                    chain=list(definition.chain),
                    description=definition.description,
                    remediation=definition.remediation,
                )
            )
    return results
