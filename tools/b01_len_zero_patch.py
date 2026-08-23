#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/ptah-transfer/tests/b01.rs")
text = path.read_text(encoding="utf-8")
old = "assert!(second.successful_sources.len() >= 1);"
new = "assert!(!second.successful_sources.is_empty());"
if text.count(old) != 1:
    raise SystemExit(f"expected one len comparison, found {text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
