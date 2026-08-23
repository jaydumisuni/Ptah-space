#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/ptah-archive-decomposition/src/b02.rs")
text = path.read_text(encoding="utf-8")
replacements = {
    'archive_spec.requested_level = "L2_inventoried".to_owned();': '"L2_inventoried".clone_into(&mut archive_spec.requested_level);',
    'archive_spec.requested_level = "L3_decomposed".to_owned();': '"L3_decomposed".clone_into(&mut archive_spec.requested_level);',
    '''    report.achieved_level = if plan.inventory.is_empty() {
        ProgressiveLevel::L1
    } else if requested_level == ProgressiveLevel::L2 {
        ProgressiveLevel::L2
    } else if plan.recovered_members.is_empty() {
        ProgressiveLevel::L2
    } else {
        ProgressiveLevel::L3
    };''': '''    report.achieved_level = if plan.inventory.is_empty() {
        ProgressiveLevel::L1
    } else if requested_level == ProgressiveLevel::L2 || plan.recovered_members.is_empty() {
        ProgressiveLevel::L2
    } else {
        ProgressiveLevel::L3
    };''',
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match for {old!r}, found {count}")
    text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")
