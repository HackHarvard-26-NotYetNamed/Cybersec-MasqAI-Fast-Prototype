from __future__ import annotations

import re
import unicodedata


def slugify(title: str) -> str:
    """Turn a heading into a URL slug: 'Hello, World!' -> 'hello-world'."""
    text = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


def word_count(text: str) -> int:
    return len(text.split())
