"""Create the reviewed, source-only repository ZIP; never archive the workspace wholesale."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path, PurePosixPath
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FILES = (
    ".gitignore", "README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md",
    "pyproject.toml", "requirements.txt", "requirements-dev.txt", "requirements-build.txt", "run.py",
    "scripts/setup-windows.ps1", "scripts/run-windows.ps1", "scripts/test-windows.ps1",
    "scripts/build-windows.ps1", "scripts/package-source.py",
    "packaging/entrypoint.py", "packaging/fix-inspector.spec",
    "resources/app.ico",
    "docs/USER_GUIDE.md", "docs/TROUBLESHOOTING.md", "docs/ARCHITECTURE.md",
    "docs/DISPLAY_PRESENTATION.md", "docs/COMPOSER_OVERLAY.example.json",
    "tests/fixtures/README.md", "tests/fixtures/COMPOSER_OVERLAY.json",
    "tests/fixtures/FIX_COMPOSER.xml", "tests/fixtures/FIX_GROUPS_NESTED.xml",
    "tests/fixtures/FIX50_MINIMAL.xml", "tests/fixtures/FIXT11_MINIMAL.xml",
)
FORBIDDEN_PARTS = {
    ".git", ".venv", "venv", ".wheelhouse", "__pycache__", "build", "dist",
    "release", ".idea", ".vscode", "reference", "prompts", "context",
}
FORBIDDEN_SUFFIXES = {
    ".exe", ".dll", ".zip", ".whl", ".pyc", ".pyo", ".log", ".fixproj",
    ".ini", ".pem", ".key", ".pfx", ".p12", ".crt", ".sqlite", ".db", ".gz",
}
PRIVATE_CONTENT = re.compile(
    r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----"
    r"|[A-Za-z]:[\\/]Users[\\/]"
    r"|/home/[A-Za-z0-9_.-]+/"
    r"|\b(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"
    r"|\bDVFIX\b"
    r"|\bAKIA[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b",
    re.IGNORECASE,
)


def version(root: Path = ROOT) -> str:
    tree = ast.parse((root / "src/fixinspector/__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if re.fullmatch(r"\d+\.\d+\.\d+(?:rc\d+)?", value):
                return value
    raise ValueError("Missing/invalid authoritative version")


def selected_files(root: Path = ROOT) -> list[Path]:
    files = {root / name for name in PUBLIC_FILES}
    files.update((root / "src").rglob("*.py"))
    files.update((root / "tests").rglob("*.py"))
    # Include a license only when the owner actually supplies one.
    files.update(path for path in (root / "LICENSE", root / "LICENSE.md") if path.is_file())
    for path in files:
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"Missing or unsafe public file: {path.relative_to(root)}")
    return sorted(files)


def audit_entry(name: str, data: bytes) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError(f"Unsafe archive path: {name}")
    if any(part.lower() in FORBIDDEN_PARTS for part in path.parts):
        raise ValueError(f"Excluded directory: {name}")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError(f"Excluded artifact: {name}")
    if path.parts[-2:] == ("resources", "app.ico"):
        # The one permitted binary source asset is the owner-provided ICO.
        if len(data) < 6:
            raise ValueError("Truncated application icon")
        reserved, kind, count = struct.unpack_from("<HHH", data)
        if reserved != 0 or kind != 1 or not 1 <= count <= 256 or len(data) < 6 + count * 16:
            raise ValueError("Invalid application icon directory")
        for index in range(count):
            size, offset = struct.unpack_from("<II", data, 6 + index * 16 + 8)
            if not size or offset < 6 + count * 16 or offset + size > len(data):
                raise ValueError("Invalid application icon image")
        return
    contents = data.decode("utf-8-sig")
    if PRIVATE_CONTENT.search(contents):
        # Never print a potentially sensitive matching value.
        raise ValueError(f"Private-data pattern requires review: {name}")


def audit_archive(path: Path, release_version: str) -> int:
    prefix = f"FIX-Inspector-{release_version}/"
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not names:
            raise ValueError("Empty or duplicate archive entries")
        for name in names:
            if not name.startswith(prefix):
                raise ValueError("Archive must have exactly one versioned root")
            audit_entry(name, archive.read(name))
        if prefix + "README.md" not in names:
            raise ValueError("Missing README")
        if archive.testzip() is not None:
            raise ValueError("ZIP integrity check failed")
        return len(names)


def main() -> None:
    release_version = version()
    destination = ROOT / "release" / f"FIX-Inspector-{release_version}-GitHub-Source.zip"
    destination.parent.mkdir(exist_ok=True)
    temporary = destination.with_suffix(".zip.tmp")
    files = selected_files()
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            name = f"FIX-Inspector-{release_version}/{path.relative_to(ROOT).as_posix()}"
            data = path.read_bytes()
            audit_entry(name, data)
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    count = audit_archive(temporary, release_version)
    temporary.replace(destination)
    print(f"Source ZIP: {destination}\nFiles audited: {count}")
    print(f"SHA-256: {hashlib.sha256(destination.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
