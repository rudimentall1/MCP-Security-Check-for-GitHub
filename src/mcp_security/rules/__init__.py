"""Default rule set assembly.

``default_rules()`` returns the built-in MSC00x rule instances in a stable
order (matches numeric rule_id order for readable output). This is the
single place that needs to change when a new rule is added.
"""

from __future__ import annotations

from typing import List

from mcp_security.rules.base import Rule, RuleEngine
from mcp_security.rules.combinations import (
    FilesystemAndExternalNetworkRule,
    PackageInstallAndExecuteRule,
    SecretAndExternalNetworkRule,
    ShellAndExternalNetworkRule,
)
from mcp_security.rules.credentials import (
    CredentialFileAccessRule,
    HardcodedSecretRule,
    SecretAccessRule,
)
from mcp_security.rules.dangerous_tools import (
    DangerousMcpToolRule,
    DynamicCodeExecutionRule,
    ExternalInstructionFetchRule,
    ObfuscatedInstructionRule,
    RemoteScriptExecutionRule,
    UnknownPublisherRule,
    UnpinnedDependencyRule,
    UnverifiedRemoteSourceRule,
)
from mcp_security.rules.filesystem import UnrestrictedFilesystemWriteRule
from mcp_security.rules.network import UnrestrictedNetworkRule
from mcp_security.rules.shell import ArbitraryShellExecutionRule


def default_rules() -> List[Rule]:
    return [
        ArbitraryShellExecutionRule(),
        SecretAccessRule(),
        SecretAndExternalNetworkRule(),
        FilesystemAndExternalNetworkRule(),
        ShellAndExternalNetworkRule(),
        UnrestrictedFilesystemWriteRule(),
        CredentialFileAccessRule(),
        RemoteScriptExecutionRule(),
        UnrestrictedNetworkRule(),
        PackageInstallAndExecuteRule(),
        DynamicCodeExecutionRule(),
        DangerousMcpToolRule(),
        ExternalInstructionFetchRule(),
        ObfuscatedInstructionRule(),
        UnpinnedDependencyRule(),
        UnverifiedRemoteSourceRule(),
        UnknownPublisherRule(),
        HardcodedSecretRule(),
    ]


def build_default_engine() -> RuleEngine:
    return RuleEngine(default_rules())


__all__ = ["default_rules", "build_default_engine", "Rule", "RuleEngine"]
