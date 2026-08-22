from mcp_security.analyzers.attack_paths import detect_attack_paths


def test_no_attack_path_for_single_capability():
    paths = detect_attack_paths({"filesystem.read"})
    assert paths == []


def test_secrets_and_external_network_triggers_ap001():
    paths = detect_attack_paths({"secrets.read", "network.external"})
    ids = {p.path_id for p in paths}
    assert "AP001" in ids
    ap001 = next(p for p in paths if p.path_id == "AP001")
    assert ap001.severity.value == "critical"


def test_filesystem_read_and_external_network_triggers_ap002():
    paths = detect_attack_paths({"filesystem.read", "network.external"})
    ids = {p.path_id for p in paths}
    assert "AP002" in ids


def test_filesystem_write_and_shell_execute_triggers_ap003():
    paths = detect_attack_paths({"filesystem.write", "shell.execute"})
    ids = {p.path_id for p in paths}
    assert "AP003" in ids


def test_shell_execute_and_external_network_triggers_ap004():
    paths = detect_attack_paths({"shell.execute", "network.external"})
    ids = {p.path_id for p in paths}
    assert "AP004" in ids


def test_package_install_and_execute_triggers_ap005():
    paths = detect_attack_paths({"package.install", "package.execute"})
    ids = {p.path_id for p in paths}
    assert "AP005" in ids


def test_credentials_and_external_network_triggers_ap006():
    paths = detect_attack_paths({"credentials.read", "network.external"})
    ids = {p.path_id for p in paths}
    assert "AP006" in ids


def test_full_chain_triggers_ap007_multi_step():
    paths = detect_attack_paths({"filesystem.write", "shell.execute", "network.external"})
    ids = {p.path_id for p in paths}
    assert "AP007" in ids
    # The multi-step path should also imply the pairwise ones fire.
    assert "AP003" in ids
    assert "AP004" in ids


def test_attack_path_chain_is_ordered_and_stringifies():
    paths = detect_attack_paths({"secrets.read", "network.external"})
    ap001 = next(p for p in paths if p.path_id == "AP001")
    assert ap001.chain_str() == "secrets.read → network.external"
