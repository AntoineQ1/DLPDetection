def mask(s: str, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    if len(s) > keep_prefix + keep_suffix:
        masked = s[0:keep_prefix] + "*" * (len(s) - keep_prefix - keep_suffix) + s[-keep_suffix:]
    else:
        masked = "*" * len(s)

    if keep_suffix == 0 and len(s) > keep_prefix:
        masked = s[0:keep_prefix] + "*" * (len(s) - keep_prefix)
        
    return masked