"""Regression tests for security fixes."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_security.analyzers.attack_paths import detect_attack_paths
from mcp_security.discovery.mcp import discover_mcp_files
from mcp_security.discovery.files import DEFAULT_MAX_FILE_SIZE_BYTES
from mcp_security.engine import scan
from mcp_security.model.capability import Capability
from mcp_security.model.component import Component, ComponentKind


def make_component(name, capabilities):
    caps = []
    for cap_id in capabilities:
        parts = cap_id.split('.')
        caps.append(Capability(type=parts[0], action=parts[1]))
    return Component(name=name, kind=ComponentKind.MCP_SERVER, source='test', file=f'{name}.json', capabilities=caps)


def write_mcp_json(dirpath, components_data):
    """Write an MCP JSON file with given components."""
    mcp_json = os.path.join(dirpath, 'mcp.json')
    servers = {}
    for comp in components_data:
        servers[comp['name']] = {
            'command': comp.get('command', 'echo'),
            'args': comp.get('args', []),
            'env': comp.get('env', {}),
        }
    with open(mcp_json, 'w') as f:
        import json
        json.dump({'mcpServers': servers}, f)
    return mcp_json


class TestAttackPathIsolationDirect(unittest.TestCase):
    """Direct tests for detect_attack_paths."""

    def test_no_cross_component_attack_path(self):
        comp_a = make_component('A', ['secrets.read'])
        comp_b = make_component('B', ['network.external'])
        paths_a = detect_attack_paths(set(comp_a.capability_ids()))
        paths_b = detect_attack_paths(set(comp_b.capability_ids()))
        self.assertFalse(any(p.path_id == 'AP001' for p in paths_a))
        self.assertFalse(any(p.path_id == 'AP001' for p in paths_b))

    def test_no_cross_component_multi_step_attack(self):
        comp_a = make_component('A', ['filesystem.write'])
        comp_b = make_component('B', ['shell.execute'])
        comp_c = make_component('C', ['network.external'])
        paths_a = detect_attack_paths(set(comp_a.capability_ids()))
        paths_b = detect_attack_paths(set(comp_b.capability_ids()))
        paths_c = detect_attack_paths(set(comp_c.capability_ids()))
        self.assertFalse(any(p.path_id == 'AP007' for p in paths_a))
        self.assertFalse(any(p.path_id == 'AP007' for p in paths_b))
        self.assertFalse(any(p.path_id == 'AP007' for p in paths_c))

    def test_single_component_attack_path_still_works(self):
        comp = make_component('A', ['secrets.read', 'network.external'])
        paths = detect_attack_paths(set(comp.capability_ids()))
        self.assertTrue(any(p.path_id == 'AP001' for p in paths))


class TestAttackPathIsolationViaEngine(unittest.TestCase):
    """Integration tests through the public scan() API."""

    def _write_config(self, td, filename, servers):
        import json
        fpath = os.path.join(td, filename)
        with open(fpath, 'w') as f:
            json.dump({'mcpServers': servers}, f)
        return fpath

    def test_engine_no_cross_component_ap001(self):
        """A: secrets.read, B: network.external -> no AP001 via scan()."""
        with tempfile.TemporaryDirectory() as td:
            # Component A: secrets.read (env with SECRET_KEY)
            file_a = self._write_config(td, 'mcp_a.json', {
                'A': {'command': 'echo', 'env': {'SECRET_KEY': 'x'}}
            })
            # Component B: network.external (curl with external URL)
            file_b = self._write_config(td, 'mcp_b.json', {
                'B': {'command': 'curl', 'args': ['https://example.com']}
            })
            
            report = scan(td, explicit_paths=[file_a, file_b])
            
            ap001_found = any(ap.path_id == 'AP001' for ap in report.attack_paths)
            self.assertFalse(ap001_found)

    def test_engine_no_cross_component_ap007(self):
        """A: filesystem.write, B: shell.execute, C: network.external -> no AP007."""
        with tempfile.TemporaryDirectory() as td:
            file_a = self._write_config(td, 'mcp_a.json', {
                'A': {'command': 'write-tool'}
            })
            file_b = self._write_config(td, 'mcp_b.json', {
                'B': {'command': 'bash -c'}
            })
            file_c = self._write_config(td, 'mcp_c.json', {
                'C': {'command': 'curl', 'args': ['https://example.com']}
            })
            
            report = scan(td, explicit_paths=[file_a, file_b, file_c])
            
            ap007_found = any(ap.path_id == 'AP007' for ap in report.attack_paths)
            self.assertFalse(ap007_found)

    def test_engine_single_component_ap001(self):
        """A: secrets.read + network.external -> AP001 via scan()."""
        with tempfile.TemporaryDirectory() as td:
            file_a = self._write_config(td, 'mcp.json', {
                'A': {
                    'url': 'https://api.example.com',
                    'env': {'SECRET_KEY': 'x'}
                }
            })
            
            report = scan(td, explicit_paths=[file_a])
            
            ap001_found = any(ap.path_id == 'AP001' for ap in report.attack_paths)
            self.assertTrue(ap001_found)


class TestExplicitFileSecurity(unittest.TestCase):
    """Explicit --file paths must respect security checks."""

    def test_explicit_file_normal_works(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            normal_file = os.path.join(temp_dir, "custom-config.json")
            with open(normal_file, "wb") as f:
                f.write(b"{}")
            result = discover_mcp_files(root=temp_dir, explicit_paths=[normal_file])
            result_paths = [d.path for d in result]
            self.assertIn(os.path.abspath(normal_file), result_paths)

    def test_explicit_file_too_large_rejected(self):
        """An explicitly requested file over the limit must fail, not be skipped."""
        with tempfile.TemporaryDirectory() as temp_dir:
            large_file = os.path.join(temp_dir, "large.json")
            with open(large_file, "wb") as f:
                f.write(b"x" * (DEFAULT_MAX_FILE_SIZE_BYTES + 1024))
            with self.assertRaisesRegex(ValueError, "exceeds the .*byte limit"):
                discover_mcp_files(root=temp_dir, explicit_paths=[large_file])

    def test_explicit_file_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = os.path.join(temp_dir, "target.json")
            with open(target, "wb") as f:
                f.write(b"{}")
            symlink = target + ".symlink"
            try:
                os.symlink(target, symlink)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks not supported")
                return
            with self.assertRaisesRegex(ValueError, "is a symlink"):
                discover_mcp_files(root=temp_dir, explicit_paths=[symlink])


class TestCapabilityDiffComponentIdentity(unittest.TestCase):
    """Regression tests for capability diff with component identity."""

    def _make_comp(self, name, cap_type, cap_action, target):
        from mcp_security.model.capability import Capability as C
        from mcp_security.model.component import Component as Comp, ComponentKind
        cap = C(type=cap_type, action=cap_action, target=target)
        return Comp(name=name, kind=ComponentKind.MCP_SERVER, source='test', file=f'{name}.json', capabilities=[cap])

    def test_component_b_target_change_detected(self):
        """TEST 1: B: ./secrets -> / must be detected as changed."""
        from mcp_security.diff.capability_diff import diff_components

        base = [
            self._make_comp('A', 'filesystem', 'read', './project'),
            self._make_comp('B', 'filesystem', 'read', './secrets'),
        ]
        head = [
            self._make_comp('A', 'filesystem', 'read', './project'),
            self._make_comp('B', 'filesystem', 'read', '/'),
        ]

        summary, _ = diff_components(base, head)

        self.assertEqual(len(summary.changed), 1)
        self.assertEqual(summary.changed[0]['capability'], 'filesystem.read')
        self.assertEqual(summary.changed[0]['before_target'], './secrets')
        self.assertEqual(summary.changed[0]['after_target'], '/')

    def test_same_capability_id_different_components_no_cross_compare(self):
        """TEST 2: Same capability ID in different components must not cross-compare."""
        from mcp_security.diff.capability_diff import diff_components

        base = [
            self._make_comp('A', 'filesystem', 'read', './project'),
            self._make_comp('B', 'filesystem', 'read', './secrets'),
        ]
        head = [
            self._make_comp('A', 'filesystem', 'read', './project'),
            self._make_comp('B', 'filesystem', 'read', './secrets'),
        ]

        summary, _ = diff_components(base, head)

        self.assertEqual(len(summary.changed), 0)
        self.assertEqual(len(summary.added), 0)
        self.assertEqual(len(summary.removed), 0)

    def test_single_component_target_change_detected(self):
        """TEST 3: Single component target change must be detected."""
        from mcp_security.diff.capability_diff import diff_components

        base = [self._make_comp('A', 'filesystem', 'read', './project')]
        head = [self._make_comp('A', 'filesystem', 'read', '/')]

        summary, _ = diff_components(base, head)

        self.assertEqual(len(summary.changed), 1)
        self.assertEqual(summary.changed[0]['capability'], 'filesystem.read')
        self.assertEqual(summary.changed[0]['before_target'], './project')
        self.assertEqual(summary.changed[0]['after_target'], '/')

    def test_identical_components_unchanged(self):
        """TEST 4: Same component + capability + target must be unchanged."""
        from mcp_security.diff.capability_diff import diff_components

        base = [self._make_comp('A', 'filesystem', 'read', './project')]
        head = [self._make_comp('A', 'filesystem', 'read', './project')]

        summary, _ = diff_components(base, head)

        self.assertEqual(len(summary.changed), 0)
        self.assertEqual(len(summary.added), 0)
        self.assertEqual(len(summary.removed), 0)
        self.assertEqual(len(summary.unchanged), 1)


    def test_capability_moved_to_different_component_not_same(self):
        """TEST: A has filesystem.read in BASE, B has it in HEAD - must NOT be same."""
        from mcp_security.diff.capability_diff import diff_components

        base = [self._make_comp('A', 'filesystem', 'read', None)]
        head = [self._make_comp('B', 'filesystem', 'read', None)]

        summary, _ = diff_components(base, head)

        self.assertEqual(len(summary.removed), 1)
        self.assertEqual(summary.removed[0], 'filesystem.read')
        self.assertEqual(len(summary.added), 1)
        self.assertEqual(summary.added[0], 'filesystem.read')
        self.assertEqual(len(summary.changed), 0)
        self.assertEqual(len(summary.unchanged), 0)

    def test_duplicate_capability_id_same_component(self):
        """TEST: Duplicate capability ID in same component must not duplicate in output."""
        from mcp_security.diff.capability_diff import diff_components
        from mcp_security.model.capability import Capability as C

        base_caps = [C(type='filesystem', action='read', target='./a'), C(type='filesystem', action='read', target='./b')]
        head_caps = [C(type='filesystem', action='read', target='./a'), C(type='filesystem', action='read', target='./b')]
        base = [Component(name='A', kind=ComponentKind.MCP_SERVER, source='test', file='A.json', capabilities=base_caps)]
        head = [Component(name='A', kind=ComponentKind.MCP_SERVER, source='test', file='A.json', capabilities=head_caps)]

        summary, _ = diff_components(base, head)

        self.assertEqual(len(summary.unchanged), 1)
        self.assertEqual(len(summary.changed), 0)
        self.assertEqual(len(summary.added), 0)
        self.assertEqual(len(summary.removed), 0)


if __name__ == '__main__':
    unittest.main()
