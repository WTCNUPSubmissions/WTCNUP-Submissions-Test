#!/usr/bin/env python3
"""Phase 0 validator/package builder.

Security properties:
- never executes submission files
- rejects symlinks, path traversal, archives and executables by magic
- verifies every declared size/SHA-256
- writes only to out/ and does not use release secrets
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SUBMISSIONS = ROOT / "submissions"
OUT = ROOT / "out"

ALLOWED_EXTENSIONS = {
    ".blk", ".csv", ".json", ".txt", ".yml", ".yaml", ".ini",
    ".dds", ".png", ".tga", ".ogg", ".wav",
}
ARCHIVE_MAGIC = (
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",
    b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b",
)
MAX_FILES = 300
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILE = 10 * 1024 * 1024
INVALID_CHARS = set('<>:"|?*')
RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def fail(message: str) -> None:
    print(f"::error::{message}")
    sys.exit(1)


def safe_path(relative: str) -> None:
    if not relative or len(relative) > 240:
        fail(f"unsafe/too-long path: {relative!r}")
    if "\\" in relative or relative.startswith("/") or ":" in relative:
        fail(f"unsafe path: {relative!r}")
    parts = PurePosixPath(relative).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        fail(f"unsafe path segment: {relative!r}")
    for part in parts:
        if len(part) > 120 or part.endswith((" ", ".")):
            fail(f"unsafe path segment: {relative!r}")
        if any(ord(ch) < 32 or ch in INVALID_CHARS for ch in part):
            fail(f"unsafe character in path: {relative!r}")
        if part.split(".")[0].casefold() in RESERVED:
            fail(f"Windows reserved name: {relative!r}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_magic(path: Path) -> None:
    with path.open("rb") as handle:
        prefix = handle.read(512)
    if any(prefix.startswith(sig) for sig in ARCHIVE_MAGIC):
        fail(f"archive content is not allowed: {path.name}")
    if prefix.startswith(b"MZ"):
        fail(f"executable content is not allowed: {path.name}")


def main() -> None:
    if not SUBMISSIONS.is_dir():
        fail("submissions/ is missing")
    candidates = [p for p in SUBMISSIONS.iterdir() if p.is_dir() and (p / "submission.json").is_file()]
    if len(candidates) != 1:
        fail(f"PR must contain exactly one submissions/<uid>/submission.json, found {len(candidates)}")
    submission_dir = candidates[0]
    metadata = json.loads((submission_dir / "submission.json").read_text(encoding="utf-8"))

    required = ("id", "github_user", "author_name", "work_name", "game_version",
                "translation_version", "file_count", "total_size", "files", "submitted_at")
    for key in required:
        if key not in metadata:
            fail(f"submission.json missing field: {key}")

    pr_author = os.environ.get("PR_AUTHOR", "").strip()
    if pr_author and str(metadata["github_user"]).casefold() != pr_author.casefold():
        fail("submission.json github_user does not match the Pull Request author")

    files_root = submission_dir / "files"
    if not files_root.is_dir():
        fail("submission files/ directory is missing")

    actual: dict[str, dict] = {}
    total = 0
    casefold_seen: set[str] = set()
    for current, dirs, names in os.walk(files_root, followlinks=False):
        current_path = Path(current)
        for name in list(dirs):
            if (current_path / name).is_symlink():
                fail(f"symlink directory is not allowed: {name}")
        for name in names:
            path = current_path / name
            if path.is_symlink():
                fail(f"symlink file is not allowed: {name}")
            relative = path.relative_to(files_root).as_posix()
            safe_path(relative)
            folded = relative.casefold()
            if folded in casefold_seen:
                fail(f"case-insensitive path collision: {relative}")
            casefold_seen.add(folded)
            extension = path.suffix.lower()
            if extension not in ALLOWED_EXTENSIONS:
                fail(f"extension not allowed: {relative}")
            check_magic(path)
            size = path.stat().st_size
            if size > MAX_FILE:
                fail(f"file too large: {relative}")
            actual[relative] = {"path": relative, "size": size, "sha256": sha256_file(path)}
            total += size
            if len(actual) > MAX_FILES:
                fail("too many files")
            if total > MAX_TOTAL:
                fail("submission too large")

    declared: dict[str, dict] = {}
    for item in metadata["files"]:
        if not isinstance(item, dict):
            fail("invalid files entry")
        path = str(item.get("path", ""))
        safe_path(path)
        declared[path] = item
    if set(actual) != set(declared):
        fail(f"declared/actual file set mismatch: declared={sorted(declared)} actual={sorted(actual)}")
    for path, info in actual.items():
        item = declared[path]
        if int(item.get("size", -1)) != info["size"]:
            fail(f"size mismatch: {path}")
        if str(item.get("sha256", "")).lower() != info["sha256"]:
            fail(f"sha256 mismatch: {path}")

    if int(metadata["file_count"]) != len(actual):
        fail("file_count mismatch")
    if int(metadata["total_size"]) != total:
        fail("total_size mismatch")

    OUT.mkdir(exist_ok=True)
    manifest = {
        "schema_version": 1,
        "submission_id": metadata["id"],
        "github_user": metadata["github_user"],
        "author_name": metadata["author_name"],
        "work_name": metadata["work_name"],
        "game_version": metadata["game_version"],
        "translation_version": metadata["translation_version"],
        "pr_number": metadata.get("pr_number"),
        "file_count": len(actual),
        "total_size": total,
        "files": [actual[k] for k in sorted(actual)],
        "packaged_at": datetime.now(timezone.utc).isoformat(),
    }
    package = OUT / "submission-package.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("submission.json", json.dumps(metadata, ensure_ascii=False, indent=2))
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        for path in sorted(actual):
            archive.write(files_root / path, f"files/{path}")

    package_sha = sha256_file(package)
    (OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "SHA256.txt").write_text(f"{package_sha}  submission-package.zip\n", encoding="utf-8")
    print(f"::notice::validated {len(actual)} files, {total} bytes")
    print(f"::notice::ZIP {package.name}, {package.stat().st_size} bytes, SHA256 {package_sha}")


if __name__ == "__main__":
    main()
