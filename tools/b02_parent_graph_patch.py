#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


source_path = Path("crates/ptah-archive-decomposition/src/b02.rs")
source = source_path.read_text(encoding="utf-8")
source = replace_once(
    source,
    '''    let recovered: HashMap<usize, &RecoveredMember> = plan
        .recovered_members
        .iter()
        .map(|member| (member.inventory_index, member))
        .collect();
    for (index, entry) in plan.inventory.iter().enumerate() {
        let parent_path = logical_parent(&entry.logical_path);
        let type_assessment = recovered
''',
    '''    let recovered: HashMap<usize, &RecoveredMember> = plan
        .recovered_members
        .iter()
        .map(|member| (member.inventory_index, member))
        .collect();
    let container_paths: HashMap<&str, String> = plan
        .recovered_members
        .iter()
        .map(|member| (member.member_sha256.as_str(), member.logical_path.clone()))
        .collect();
    for (index, entry) in plan.inventory.iter().enumerate() {
        let parent_path = recovered
            .get(&index)
            .and_then(|member| member.parent_inventory_index)
            .and_then(|parent_index| plan.inventory.get(parent_index))
            .map(|parent| parent.logical_path.clone())
            .or_else(|| container_paths.get(entry.container_sha256.as_str()).cloned());
        let type_assessment = recovered
''',
    "authoritative parent projection",
)
source = replace_once(
    source,
    '''fn logical_parent(path: &str) -> Option<String> {
    path.rsplit_once('/').map(|(parent, _)| parent.to_owned())
}

''',
    "",
    "remove path-derived parent helper",
)
source_path.write_text(source, encoding="utf-8")

tests_path = Path("crates/ptah-archive-decomposition/tests/b02.rs")
tests = tests_path.read_text(encoding="utf-8")
tests = replace_once(tests, 'path: "readme.txt".to_owned(),', 'path: "folder/readme.txt".to_owned(),', "root slash path")
tests = replace_once(tests, 'path: "deep.arc".to_owned(),', 'path: "folder/deep.arc".to_owned(),', "nested slash path")
tests = replace_once(
    tests,
    '''    assert!(
        report
            .children
            .iter()
            .any(|child| child.child_path == "readme.txt")
    );
    assert!(
        report
            .children
            .iter()
            .all(|child| !child.child_path.contains('/'))
    );
''',
    '''    let root_slash_member = report
        .children
        .iter()
        .find(|child| child.child_path == "folder/readme.txt")
        .expect("root member with slash retained");
    assert!(root_slash_member.parent_path.is_none());
    assert!(report.children.iter().all(|child| {
        child.parent_path.as_deref() != Some("folder")
    }));
''',
    "L2 root parent assertion",
)
tests = tests.replace('"nested.arc/deep.arc"', '"nested.arc/folder/deep.arc"')
tests = tests.replace('"nested.arc/deep.arc/leaf.txt"', '"nested.arc/folder/deep.arc/leaf.txt"')
tests = tests.replace('Some("nested.arc/deep.arc")', 'Some("nested.arc/folder/deep.arc")')
tests_path.write_text(tests, encoding="utf-8")
