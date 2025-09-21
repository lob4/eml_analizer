from __future__ import annotations

from pathlib import Path


class EmlReader:
    """Utility class for working with ``.eml`` files stored in a directory."""

    def __init__(self, directory: Path | str) -> None:
        self._directory = Path(directory)
        if not self._directory.exists():
            raise FileNotFoundError(f"Directory '{self._directory}' does not exist")
        if not self._directory.is_dir():
            raise NotADirectoryError(f"'{self._directory}' is not a directory")

    @property
    def directory(self) -> Path:
        """Return the directory containing the ``.eml`` files."""

        return self._directory

    def list_emls(self) -> list[Path]:
        """Return a sorted list of ``.eml`` files from the directory."""

        eml_files = [
            path
            for path in self._directory.iterdir()
            if path.is_file() and path.suffix.lower() == ".eml"
        ]
        return sorted(eml_files)

    def load_eml_by_index(self, index: int) -> bytes:
        """Load the content of an ``.eml`` file selected by its index."""

        eml_files = self.list_emls()
        try:
            selected = eml_files[index]
        except IndexError as exc:
            raise IndexError(
                f"Index {index} is out of range for {len(eml_files)} available .eml files"
            ) from exc
        return selected.read_bytes()


__all__ = ["EmlReader"]
