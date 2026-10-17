"""Select upstream OWASP-tagged rules; prefix IDs as Semgrep does for file configs."""
from pathlib import Path
from ruamel.yaml import YAML

root = Path('/tmp/semgrep-rules')
yaml = YAML(typ='safe')
rules = []
for file in sorted(root.rglob('*.yaml')):
    if '.test.' in file.name or any(part in {'tests', 'test', '.github', 'stats'} for part in file.relative_to(root).parts):
        continue
    try:
        data = yaml.load(file.read_text())
    except Exception:
        continue  # Upstream also contains intentionally malformed rule-test fixtures.
    if not isinstance(data, dict):
        continue
    for rule in data.get('rules', []):
        if not isinstance(rule, dict) or not rule.get('metadata', {}).get('owasp'):
            continue
        if any(value is None for value in rule.values()) or rule.get('severity') not in {'ERROR', 'WARNING', 'INFO'}:
            continue
        if 'apex' in rule.get('languages', []):
            continue  # Apex needs a proprietary parser; it is explicitly outside the OSS bundle.
        rule['id'] = '.'.join(file.relative_to(root).with_suffix('').parts) + '.' + rule['id']
        rules.append(rule)
assert rules, 'No upstream OWASP rules selected'
with Path('/opt/audit-scanners/semgrep-rules').open('w') as output:
    yaml.dump({'rules': rules}, output)
