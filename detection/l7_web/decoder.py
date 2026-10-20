import json
from urllib.parse import parse_qs


def _normalize_content_type(content_type: str) -> str:

    return content_type.split(";", 1)[0].strip().lower()


def _flatten_scalars(obj) -> list[str]:
    """Recursively collect every string or numeric value inside a JSON-shaped object."""
    if isinstance(obj, (str, int, float)):
        return [str(obj)]
    if isinstance(obj, dict):
        result = []
        for value in obj.values():
            result.extend(_flatten_scalars(value))
        return result
    if isinstance(obj, list):
        result = []
        for value in obj:
            result.extend(_flatten_scalars(value))
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
                parsed_list.extend(_flatten_scalars(value))
            return parsed_list

        except Exception:
            pass

    if ct == "application/json":
        try:
            content_str = content.decode("utf-8", errors="replace")
            return _flatten_scalars(json.loads(content_str))
        except Exception:
            pass

    # Uncomment the next 3 lines to show the fix to the gzip evasion attack:
    # import gzip as _gzip
    # if content[:2] == b"\x1f\x8b":
    #     return [_gzip.decompress(content).decode("utf-8", errors="replace")]

    return [content.decode("utf-8", errors="replace")]
