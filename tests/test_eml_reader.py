from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eml_reader import EmlReader


def create_eml(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content)
    return path


def test_list_emls_returns_sorted_eml_files(tmp_path: Path) -> None:
    eml_dir = tmp_path / "emls"
    eml_dir.mkdir()
    create_eml(eml_dir, "b.eml", "second")
    create_eml(eml_dir, "a.eml", "first")
    (eml_dir / "note.txt").write_text("ignore")

    reader = EmlReader(eml_dir)

    eml_files = reader.list_emls()

    assert [path.name for path in eml_files] == ["a.eml", "b.eml"]


def test_load_eml_by_index_returns_bytes(tmp_path: Path) -> None:
    eml_dir = tmp_path / "emls"
    eml_dir.mkdir()
    create_eml(eml_dir, "first.eml", "content one")
    create_eml(eml_dir, "second.eml", "content two")

    reader = EmlReader(eml_dir)

    content = reader.load_eml_by_index(1)

    assert content == "content two".encode()


def test_load_eml_by_index_invalid_index(tmp_path: Path) -> None:
    eml_dir = tmp_path / "emls"
    eml_dir.mkdir()
    create_eml(eml_dir, "only.eml", "content")

    reader = EmlReader(eml_dir)

    with pytest.raises(IndexError):
        reader.load_eml_by_index(5)
