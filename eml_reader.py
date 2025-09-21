"""Utilities for inspecting `.eml` e-mail files using flanker."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Iterable, List, Tuple, Union

from email.utils import getaddresses
from urllib.parse import unquote


TextSource = Union[str, bytes]


class EmlParser:
    """Helper class that prints human readable details of .eml messages."""

    def __init__(self, parser: Callable[[str], Any] | None = None) -> None:
        """Initialise the reader with an optional custom flanker parser."""

        self._parser = parser or self._default_parser

    def display_eml_details(self, source: TextSource, from_file: bool = True) -> None:
        """Parse ``source`` and print the most important pieces of an e-mail."""

        message = self._load_message(source, from_file=from_file)

        subject = self._header_single_value(message, "subject")
        sender = self._header_single_value(message, "from")
        recipients = self._collect_recipients(message)
        body = self._extract_body(message)
        attachments = self._collect_attachments(message)

        print(f"Tytuł: {subject}")
        print(f"Nadawca: {sender}")
        print(f"Adresaci: {', '.join(recipients) if recipients else ''}")
        print("Treść:")
        print(body if body else "")

        if attachments:
            print("Załączniki:")
            for filename, digest in attachments:
                print(f"  - {filename}: {digest}")
        else:
            print("Załączniki: brak")

    def _default_parser(self, data: str) -> Any:
        """Parse ``data`` with flanker."""

        try:
            from flanker import mime
        except ImportError as exc:  # pragma: no cover - defensive fallback
            raise ImportError(
                "The 'flanker' package is required. Install it with 'pip install flanker'."
            ) from exc

        return mime.from_string(data)

    def _load_message(self, source: TextSource, *, from_file: bool = True) -> Any:
        """Return a flanker message parsed from ``source``."""

        raw_source = self._read_source(source, from_file=from_file)
        return self._parser(raw_source)

    def _read_source(self, source: TextSource, *, from_file: bool = True) -> str:
        """Return the textual representation of ``source``."""

        if from_file:
            if not isinstance(source, str):
                raise TypeError("Expected a file path when 'from_file' is True")
            with open(source, "rb") as file_handle:
                data = file_handle.read()
            return self._decode_bytes(data)

        if isinstance(source, str):
            return source
        if isinstance(source, bytes):
            return self._decode_bytes(source)

        raise TypeError("Expected 'source' to be 'str' or 'bytes'")

    def _decode_bytes(self, data: bytes) -> str:
        """Decode ``data`` using a best effort strategy."""

        for encoding in ("utf-8", "latin-1"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")

    def _header_single_value(self, message: Any, header_name: str) -> str:
        """Return the first value for ``header_name``."""

        values = self._get_header_values(message, header_name)
        return values[0] if values else ""

    def _get_header_values(self, message: Any, header_name: str) -> List[str]:
        """Return all values for ``header_name``."""

        collected: List[str] = []

        headers = getattr(message, "headers", None)
        if headers is not None:
            getall = getattr(headers, "getall", None)
            if callable(getall):
                collected.extend(self._normalise_header_sequence(getall(header_name, [])))
                if not collected:
                    collected.extend(
                        self._normalise_header_sequence(getall(header_name.title(), []))
                    )

            getter = getattr(headers, "get", None)
            if callable(getter):
                value = getter(header_name)
                if value:
                    collected.append(self._normalise_header_value(value))
                elif header_name.lower() != header_name:
                    value = getter(header_name.lower())
                    if value:
                        collected.append(self._normalise_header_value(value))

            if hasattr(headers, "__getitem__"):
                try:
                    value = headers[header_name]
                except Exception:  # pragma: no cover - defensive
                    value = None
                if value:
                    collected.append(self._normalise_header_value(value))

        for attribute_name in {header_name, header_name.lower(), header_name.replace("-", "_")}:
            attribute = getattr(message, attribute_name, None)
            if attribute:
                collected.append(self._normalise_header_value(attribute))

        return self._unique_preserve_order(collected)

    def _normalise_header_sequence(self, values: Any) -> List[str]:
        """Return a list of string values for ``values``."""

        if isinstance(values, (list, tuple, set)):
            return [
                normalised
                for normalised in (self._normalise_header_value(value) for value in values)
                if normalised
            ]

        value = self._normalise_header_value(values)
        return [value] if value else []

    def _normalise_header_value(self, value: Any) -> str:
        """Return ``value`` converted to text."""

        if value is None:
            return ""

        for attribute_name in ("value", "decoded", "body"):
            if hasattr(value, attribute_name):
                attribute = getattr(value, attribute_name)
                if attribute is not value:
                    normalised = self._normalise_header_value(attribute)
                    if normalised:
                        return normalised

        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return value.decode("latin-1", errors="replace")

        if isinstance(value, (list, tuple, set)):
            for item in value:
                normalised = self._normalise_header_value(item)
                if normalised:
                    return normalised
            return ""

        return str(value)

    def _unique_preserve_order(self, values: Iterable[str]) -> List[str]:
        """Return a list of unique values while preserving order."""

        seen: set[str] = set()
        result: List[str] = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _collect_recipients(self, message: Any) -> List[str]:
        """Return a list of unique recipient addresses from the message."""

        header_values: List[str] = []
        for header in ("to", "cc", "bcc"):
            header_values.extend(self._get_header_values(message, header))

        recipients: List[str] = []
        for _, address in getaddresses(header_values):
            if address and address not in recipients:
                recipients.append(address)
        return recipients

    def _extract_body(self, message: Any) -> str:
        """Extract the textual body of the message."""

        for attribute in ("text_plain", "body_text", "text", "body"):
            candidate = getattr(message, attribute, None)
            body = self._coerce_to_text(candidate, fallback_part=getattr(message, "body", None))
            if body:
                return body

        body_root = getattr(message, "body", None) or message
        texts = self._collect_textual_content(body_root)
        return "\n\n".join(texts) if texts else ""

    def _coerce_to_text(self, value: Any, fallback_part: Any = None) -> str:
        """Attempt to convert ``value`` to human readable text."""

        if value is None:
            return ""

        if isinstance(value, str):
            return value.strip()

        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8", errors="replace").strip()

        if fallback_part is not None and value is fallback_part:
            return ""

        if hasattr(value, "decoded"):
            decoded = getattr(value, "decoded")
            if isinstance(decoded, (bytes, bytearray)):
                return decoded.decode("utf-8", errors="replace").strip()
            if callable(decoded):  # pragma: no cover - defensive
                return self._coerce_to_text(decoded(), fallback_part=fallback_part)

        if hasattr(value, "to_string") and callable(value.to_string):
            return self._coerce_to_text(value.to_string(), fallback_part=fallback_part)

        return ""

    def _collect_textual_content(self, node: Any) -> List[str]:
        """Collect text from ``node`` and its children."""

        texts: List[str] = []
        visited: set[int] = set()

        def traverse(part: Any) -> None:
            if part is None:
                return
            identifier = id(part)
            if identifier in visited:
                return
            visited.add(identifier)

            if self._is_attachment(part):
                return

            parts = getattr(part, "parts", None)
            if parts:
                for child in parts:
                    traverse(child)

            body = getattr(part, "body", None)
            if body is not None and body is not part:
                nested_parts = getattr(body, "parts", None)
                if nested_parts:
                    for child in nested_parts:
                        traverse(child)

            text = self._part_text_content(part)
            if text:
                texts.append(text)

        traverse(node)
        return texts

    def _part_text_content(self, part: Any) -> str:
        """Return textual content for ``part`` if available."""

        content_type = self._part_content_type(part)
        if content_type and not content_type.startswith("text/"):
            return ""

        payload = getattr(part, "body", None)
        if payload is None and hasattr(part, "content"):
            payload = getattr(part, "content")

        data = self._payload_to_bytes(payload)
        if not data:
            return ""

        charset = self._detect_charset(part)
        try:
            return data.decode(charset, errors="replace").strip()
        except LookupError:  # pragma: no cover - defensive
            return data.decode("utf-8", errors="replace").strip()

    def _part_content_type(self, part: Any) -> str:
        """Return the content type for ``part``."""

        content_type = getattr(part, "content_type", None)
        if isinstance(content_type, str):
            return content_type.lower()

        headers = getattr(part, "headers", None)
        if headers is not None:
            getter = getattr(headers, "get", None)
            if callable(getter):
                value = getter("content-type")
                if isinstance(value, str):
                    return value.lower()

        mime_type = getattr(part, "mime_type", None)
        if isinstance(mime_type, str):
            return mime_type.lower()

        return ""

    def _detect_charset(self, part: Any) -> str:
        """Return the declared charset for ``part``."""

        for attribute_name in ("charset", "char_set", "encoding"):
            value = getattr(part, attribute_name, None)
            if isinstance(value, str):
                return value

        headers = getattr(part, "headers", None)
        if headers is not None:
            getter = getattr(headers, "get", None)
            if callable(getter):
                value = getter("content-type")
                if isinstance(value, str):
                    match = re.search(r"charset=([^;\s]+)", value, flags=re.IGNORECASE)
                    if match:
                        charset = match.group(1).strip('"')
                        return charset

        return "utf-8"

    def _collect_attachments(self, message: Any) -> List[Tuple[str, str]]:
        """Return attachment metadata along with SHA256 digests."""

        attachments: List[Tuple[str, str]] = []
        seen: set[int] = set()

        for part in self._iter_attachments(message):
            identifier = id(part)
            if identifier in seen:
                continue
            seen.add(identifier)

            filename = self._attachment_name(part)
            payload = self._payload_to_bytes(getattr(part, "body", None))
            if not payload and hasattr(part, "content"):
                payload = self._payload_to_bytes(getattr(part, "content"))

            digest = hashlib.sha256(payload).hexdigest()
            attachments.append((filename, digest))

        return attachments

    def _iter_attachments(self, message: Any) -> Iterable[Any]:
        """Yield all attachments contained in ``message``."""

        attachments = getattr(message, "attachments", None)
        if attachments:
            for attachment in attachments:
                yield attachment

        body = getattr(message, "body", None)
        if body is not None and body is not message:
            yield from self._iter_attachments(body)

        parts = getattr(message, "parts", None)
        if parts:
            for part in parts:
                if self._is_attachment(part):
                    yield part
                else:
                    yield from self._iter_attachments(part)

    def _is_attachment(self, part: Any) -> bool:
        """Return ``True`` when ``part`` looks like an attachment."""

        checker = getattr(part, "is_attachment", None)
        if callable(checker):
            try:
                if checker():
                    return True
            except TypeError:  # pragma: no cover - defensive
                pass

        headers = getattr(part, "headers", None)
        if headers is not None:
            getter = getattr(headers, "get", None)
            if callable(getter):
                disposition = getter("content-disposition")
                if isinstance(disposition, str) and "attachment" in disposition.lower():
                    return True

        if getattr(part, "disposition", None) == "attachment":
            return True

        return False

    def _attachment_name(self, attachment: Any) -> str:
        """Return the human readable name for ``attachment``."""

        for attribute_name in ("name", "filename", "file_name", "display_name", "title"):
            value = getattr(attachment, attribute_name, None)
            if value:
                return self._normalise_header_value(value)

        headers = getattr(attachment, "headers", None)
        if headers is not None:
            getter = getattr(headers, "get", None)
            if callable(getter):
                disposition = getter("content-disposition")
                if isinstance(disposition, str):
                    match = re.search(r"filename\*?=([^;]+)", disposition, flags=re.IGNORECASE)
                    if match:
                        filename = match.group(1).strip()
                        filename = filename.strip('"')
                        if filename.lower().startswith("utf-8''"):
                            filename = unquote(filename[7:])
                        return filename

        return "(brak nazwy)"

    def _payload_to_bytes(self, payload: Any) -> bytes:
        """Return ``payload`` converted to ``bytes``."""

        if payload is None:
            return b""

        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)

        decoded = getattr(payload, "decoded", None)
        if isinstance(decoded, (bytes, bytearray)):
            return bytes(decoded)
        if callable(decoded):  # pragma: no cover - defensive
            try:
                return self._payload_to_bytes(decoded())
            except TypeError:
                pass

        if hasattr(payload, "to_string") and callable(payload.to_string):
            return self._payload_to_bytes(payload.to_string())

        if hasattr(payload, "decode") and callable(payload.decode):
            try:
                decoded_value = payload.decode()
            except TypeError:
                decoded_value = None
            if decoded_value is not None:
                return self._payload_to_bytes(decoded_value)

        if isinstance(payload, str):
            return payload.encode("utf-8", errors="replace")

        return str(payload).encode("utf-8", errors="replace")


__all__ = ["EmlParser"]

