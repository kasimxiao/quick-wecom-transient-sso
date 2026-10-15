"""Offline standalone-delivery regressions; no customer credentials or live writes."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

import mapped_transient as mapped
import new_customer
from scripts import package_sso as package
from tests.test_mapped_transient import fixture

ROOT = Path(__file__).resolve().parents[1]


class Delivery(unittest.TestCase):
    def test_extracted_flow_is_unchanged(self):
        self.assertEqual(mapped.fingerprint(mapped.flows(fixture())),
                         '3fe9cf7de350ddbfc7e3ae14ba1b6984c691fffa6a2ac7549287032a41c64173')

    def test_version_and_release_inventory(self):
        self.assertEqual(package.VERSION, new_customer.VERSION)
        self.assertEqual(package.VERSION, json.loads((ROOT/'package.json').read_text())['version'])
        files = package.release_files(ROOT)
        self.assertEqual(len(files), len(set(files)))
        self.assertEqual(len(package.ASSETS), 20)
        for name in package.FILES:
            self.assertNotIn('shadow', name)
            self.assertNotIn('transient_customer', name)
            self.assertNotIn('plans/', name)

    def test_portable_archive_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)/'kit.zip'
            command = [sys.executable, str(ROOT/'scripts/package_sso.py'),
                       '--source-only', '--output', str(archive)]
            subprocess.run(command, check=True, capture_output=True)
            original = archive.read_bytes()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(original, archive.read_bytes())
            with zipfile.ZipFile(archive) as zipped:
                names = zipped.namelist()
                self.assertEqual(set(names), {package.PREFIX+x for x in package.FILES+package.ASSETS})
                self.assertFalse(any('customer.json' in x or '.ops/' in x for x in names))
                zipped.extractall(directory)
            root = Path(directory)/package.PREFIX
            result = subprocess.run([sys.executable, 'new_customer.py', 'plan', '--config',
                                     'new-customer.example.json'], cwd=root, check=True,
                                    capture_output=True, text=True)
            self.assertEqual(json.loads(result.stdout)['mode'], 'offline_plan')
            for script in ('migrate_mapped_transient.py','migrate_mapped_sso.py','retire_mapped_users.py'):
                subprocess.run([sys.executable, 'scripts/'+script, '--help'], cwd=root,
                               check=True, capture_output=True)

    def test_rejects_symlink_and_excludes_runtime_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in package.release_files(ROOT):
                dest = root/source.relative_to(ROOT)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, dest)
            secret = root/'customer.json'
            secret.touch()
            self.assertNotIn(secret, package.release_files(root))
            target = root/'README.md'
            target.unlink()
            target.symlink_to(ROOT/'README.md')
            with self.assertRaises(ValueError):
                package.release_files(root)

    def test_guides_preserve_staged_scope(self):
        guide = (ROOT/'docs/管理员映射临时用户实施.md').read_text()
        for phrase in ('migrate_mapped_transient.py prepare', 'migrate_mapped_sso.py enable',
                       'retire_mapped_users.py apply', 'after-snapshot.json', '不保证能通过普通新增用户接口恢复原 UUID'):
            self.assertIn(phrase, guide)
        self.assertIn('两阶段', (ROOT/'README.md').read_text())


if __name__ == '__main__':
    unittest.main()
