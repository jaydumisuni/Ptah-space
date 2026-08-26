from pathlib import Path

path = Path('.github/workflows/c08-device-identity-transport.yml')
text = path.read_text(encoding='utf-8')

old_trigger = '''on:\n  pull_request:\n    paths:\n      - "Cargo.toml"\n      - "Cargo.lock"\n      - "C08_DEVICE_IDENTITY_TRANSPORT.md"\n      - "crates/ptah-device-runtime/**"\n      - ".github/workflows/c08-device-identity-transport.yml"\n  workflow_dispatch:\n'''
new_trigger = '''on:\n  push:\n    branches:\n      - "c08-device-identity-transport"\n    paths:\n      - "Cargo.toml"\n      - "Cargo.lock"\n      - "C08_DEVICE_IDENTITY_TRANSPORT.md"\n      - "crates/ptah-device-runtime/**"\n      - ".github/workflows/c08-device-identity-transport.yml"\n  pull_request:\n    paths:\n      - "Cargo.toml"\n      - "Cargo.lock"\n      - "C08_DEVICE_IDENTITY_TRANSPORT.md"\n      - "crates/ptah-device-runtime/**"\n      - ".github/workflows/c08-device-identity-transport.yml"\n  workflow_dispatch:\n'''
if text.count(old_trigger) != 1:
    raise SystemExit(f'expected one C08 trigger block, found {text.count(old_trigger)}')
text = text.replace(old_trigger, new_trigger, 1)

old_base = '''          if [ -n "${PTAH_PR_BASE:-}" ]; then\n            test "$(git merge-base "$PTAH_C08_BASE_SHA" "$PTAH_PR_BASE")" = "$PTAH_C08_BASE_SHA"\n            base_drift="$(git diff --name-only "$PTAH_C08_BASE_SHA" "$PTAH_PR_BASE")"\n            for path in "${protected[@]}"; do\n              if printf '%s\\n' "$base_drift" | grep -Fxq "$path"; then\n                echo "C08 PR base drift overlaps protected C08 surface: $path" >&2\n                exit 1\n              fi\n            done\n          fi\n'''
new_base = '''          proof_base="${PTAH_PR_BASE:-}"\n          if [ -z "$proof_base" ]; then\n            git fetch --no-tags origin main\n            proof_base="$(git rev-parse FETCH_HEAD)"\n            printf 'C08_PUSH_BASE=%s\\n' "$proof_base"\n          else\n            printf 'C08_PR_BASE=%s\\n' "$proof_base"\n          fi\n          test "$(git merge-base "$PTAH_C08_BASE_SHA" "$proof_base")" = "$PTAH_C08_BASE_SHA"\n          base_drift="$(git diff --name-only "$PTAH_C08_BASE_SHA" "$proof_base")"\n          for path in "${protected[@]}"; do\n            if printf '%s\\n' "$base_drift" | grep -Fxq "$path"; then\n              echo "C08 proof base drift overlaps protected C08 surface: $path" >&2\n              exit 1\n            fi\n          done\n          mkdir -p /tmp/c08\n          printf '%s\\n' "$proof_base" > /tmp/c08/proof-base.txt\n'''
if text.count(old_base) != 1:
    raise SystemExit(f'expected one C08 PR-base block, found {text.count(old_base)}')
text = text.replace(old_base, new_base, 1)

old_required = '''              'workspace-tests.txt', 'acceptance-contract.md',\n          ]\n'''
new_required = '''              'workspace-tests.txt', 'acceptance-contract.md', 'proof-base.txt',\n          ]\n'''
if text.count(old_required) != 1:
    raise SystemExit(f'expected one proof required-list tail, found {text.count(old_required)}')
text = text.replace(old_required, new_required, 1)

old_manifest = '''          head = (root / 'exact-head.txt').read_text(encoding='utf-8').strip()\n          if head != os.environ['PTAH_EXACT_SHA']:\n              raise SystemExit('C08 proof head mismatch')\n          manifest = {\n'''
new_manifest = '''          head = (root / 'exact-head.txt').read_text(encoding='utf-8').strip()\n          if head != os.environ['PTAH_EXACT_SHA']:\n              raise SystemExit('C08 proof head mismatch')\n          proof_base = (root / 'proof-base.txt').read_text(encoding='utf-8').strip()\n          if not proof_base:\n              raise SystemExit('C08 proof base missing')\n          manifest = {\n'''
if text.count(old_manifest) != 1:
    raise SystemExit(f'expected one manifest head block, found {text.count(old_manifest)}')
text = text.replace(old_manifest, new_manifest, 1)

old_field = '''              'accepted_construction_base': os.environ['PTAH_C08_BASE_SHA'],\n              'workflow_run_id': int(os.environ['RUN_ID']),\n'''
new_field = '''              'accepted_construction_base': os.environ['PTAH_C08_BASE_SHA'],\n              'proof_base_commit': proof_base,\n              'workflow_run_id': int(os.environ['RUN_ID']),\n'''
if text.count(old_field) != 1:
    raise SystemExit(f'expected one manifest construction-base field, found {text.count(old_field)}')
text = text.replace(old_field, new_field, 1)

for needle in (
    'push:\n    branches:\n      - "c08-device-identity-transport"',
    'git fetch --no-tags origin main',
    'proof-base.txt',
    "'proof_base_commit': proof_base",
):
    if needle not in text:
        raise SystemExit(f'missing activation invariant: {needle}')

path.write_text(text, encoding='utf-8')
print('C08_PERMANENT_PUSH_PROOF_ACTIVATION=READY')
