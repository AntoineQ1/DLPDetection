"""HTTP body decoder (Workstream B).

Extract scannable text values from an HTTP request body, given its raw
bytes and Content-Type. 

Supported content types:
    - application/x-www-form-urlencoded  (HTML form POSTs)
    - application/json                    (incl. arbitrarily nested)
    - anything else                       (treated as plain text)

multipart/form-data is intentionally out of scope for this project.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs


def _normalize_content_type(content_type: str) -> str:

    return content_type.split(";", 1)[0].strip().lower()


def _flatten_strings(obj) -> list[str]:
    """Recursively collect every string value inside a JSON-shaped object.
    """
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        result = []
        for value in obj.values():
            result.extend(_flatten_strings(value))
        return result
    if isinstance(obj, list):
        result = []
        for value in obj:
            result.extend(_flatten_strings(value))
        return result
    return []


def decode_body(content: bytes, content_type: str) -> list[str]:
    
    if not content:
        return []

    ct = _normalize_content_type(content_type)

    if ct == "application/x-www-form-urlencoded":
        try:
            content_str = content.decode("utf-8", errors="replace")
            parsed = parse_qs(content_str, keep_blank_values=True)
            parsed_list = []
            for value in parsed.values():
                parsed_list.extend(_flatten_strings(value))
            return parsed_list

        except Exception:
            pass

    if ct == "application/json":
        try:
            content_str = content.decode("utf-8", errors="replace")
            return _flatten_strings(json.loads(content_str))
        except Exception:
            pass 

    return [content.decode("utf-8", errors="replace")]
