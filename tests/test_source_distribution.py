"""Public package/version regression checks; no release artifact is required."""

import importlib.util
from pathlib import Path
import re
import tomllib
import unittest

from fixinspector import __version__

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("source_packager", ROOT / "scripts/package-source.py")
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class SourceDistributionTests(unittest.TestCase):
    def test_metadata_and_packager_share_version_authority(self):
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(["version"], metadata["project"]["dynamic"])
        self.assertEqual("fixinspector.__version__", metadata["tool"]["setuptools"]["dynamic"]["version"]["attr"])
        self.assertEqual(__version__, packager.version())

    def test_public_allowlist_excludes_saved_private_keys_and_artifacts(self):
        paths = packager.selected_files()
        for path in paths:
            packager.audit_entry(path.relative_to(ROOT).as_posix(), path.read_bytes())
        self.assertTrue(any(path.name == "tls_fixture.py" for path in paths))
        self.assertFalse(any(path.suffix == ".pem" for path in paths))

    def test_audit_rejects_generated_artifacts_and_private_material(self):
        for name in ("dist/app.py", "src/__pycache__/a.pyc", "release/old.zip", "private.pem"):
            with self.assertRaises(ValueError):
                packager.audit_entry(name, b"")
        # Construct markers to avoid storing a private-key block in the test itself.
        marker = ("-----BEGIN " + "PRIVATE KEY-----").encode()
        with self.assertRaises(ValueError):
            packager.audit_entry("example.txt", marker)

    def test_readme_script_commands_and_local_links_exist(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for script in re.findall(r"scripts[\\/]([\w-]+\.(?:ps1|py))", readme):
            self.assertTrue((ROOT / "scripts" / script).is_file(), script)
        for link in re.findall(r"\]\(([^)]+)\)", readme):
            self.assertTrue((ROOT / link).is_file(), link)

    def test_icon_is_the_only_binary_resource_and_is_valid(self):
        icon = ROOT / "resources/app.ico"
        self.assertIn(icon, packager.selected_files())
        packager.audit_entry("resources/app.ico", icon.read_bytes())
        with self.assertRaises(ValueError):
            packager.audit_entry("resources/app.ico", b"not an icon")

    def test_public_source_and_documentation_have_no_literal_em_dash(self):
        for path in packager.selected_files():
            if path.suffix != ".ico":
                self.assertNotIn("\u2014", path.read_text(encoding="utf-8-sig"), path.name)
