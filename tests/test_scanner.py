import tempfile
import unittest
from pathlib import Path
from sentinelscan.scanner import scan_directory, scan_file, report


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'sample.py'

    def test_hardcoded_secret(self):
        self.path.write_text('api_key = "demo-not-real"\n', encoding='utf-8')
        self.assertIn('HARDCODED_SECRET', [f['rule'] for f in scan_file(self.path)])

    def test_dynamic_execution(self):
        self.path.write_text('eval("1+1")\n', encoding='utf-8')
        self.assertIn('DYNAMIC_EXECUTION', [f['rule'] for f in scan_file(self.path)])

    def test_shell_true(self):
        self.path.write_text('import subprocess\nsubprocess.run("echo hello", shell=True)\n', encoding='utf-8')
        self.assertIn('SHELL_TRUE', [f['rule'] for f in scan_file(self.path)])

    def test_safe_code(self):
        self.path.write_text('print("hello")\n', encoding='utf-8')
        self.assertEqual(scan_file(self.path), [])

    def test_skips_virtualenv(self):
        hidden = Path(self.temp.name) / '.venv'
        hidden.mkdir()
        (hidden / 'bad.py').write_text('eval("1")\n')
        self.assertEqual(scan_directory(self.temp.name), [])

    def test_json_report(self):
        self.path.write_text('password = "example"\n')
        self.assertEqual(report(self.temp.name)['finding_count'], 1)


if __name__ == '__main__':
    unittest.main()
