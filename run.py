from __future__ import annotations

import sys
from pathlib import Path


def _add_source_tree() -> None:
    source_tree = Path(__file__).resolve().parent / "src"
    source_text = str(source_tree)
    if source_text not in sys.path:
        sys.path.insert(0, source_text)


if __name__ == "__main__":
    _add_source_tree()
    from fixinspector.app import main

    raise SystemExit(main())

