"""Build dist/hardn.pyz: a single-file, zero-dependency executable (needs only python3 >= 3.9)."""
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "app"
        shutil.copytree(ROOT / "hardn", stage / "hardn", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (stage / "__main__.py").write_text("import sys\n\nfrom hardn.cli import main\n\nsys.exit(main())\n")
        target = dist / "hardn.pyz"
        zipapp.create_archive(stage, target, interpreter="/usr/bin/env python3", compressed=True)
    print(f"built {target.relative_to(ROOT)} ({target.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
