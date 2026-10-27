"""Prepare a wheel-only Python test environment from requirement files; never run target code or build hooks.

Runs with network access before reviewers start. Only the trusted uv binary and a managed CPython run here.
No target setup.py, PEP 517 backend or installed package executes during this step: wheels are unpacked, not built,
and the new environment's interpreter is never started while the network is attached (its .pth files could run).
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

work = Path(os.environ.get('AUDIT_WORK', '/work'))
source = (work / 'src').resolve()
venv = work / 'venv'
SKIP = {'.git', 'node_modules', 'target', 'dist', '.venv', 'venv', '__pycache__', '.cargo'}
PROJECT_FILES = re.compile(r'^(?:requirements[\w.-]*\.(?:txt|in)|pyproject\.toml|setup\.cfg|setup\.py|pytest\.ini|tox\.ini|Pipfile(?:\.lock)?|poetry\.lock|uv\.lock|\.python-version)$')
TEST_FILE = re.compile(r'^(?:conftest|test_.*|.*_test)\.py$')
REFUSED = re.compile(r'^(?:-e\b|--editable|--index-url|-i\b|--extra-index-url|--find-links|-f\b|--trusted-host|--no-binary|--pre\b)|://|^git\+|\s@\s')


def walk(root, depth=0):
    if depth > 6:
        return
    for entry in sorted(root.iterdir()):
        if entry.is_symlink():
            continue
        if entry.is_dir() and entry.name not in SKIP:
            yield from walk(entry, depth + 1)
        elif entry.is_file():
            yield entry


def project_dirs():
    files = list(walk(source))
    projects = {f.parent for f in files if PROJECT_FILES.match(f.name)}
    counts = {}
    for f in files:
        if not TEST_FILE.match(f.name):
            continue
        for parent in [f.parent, *f.parents]:
            if parent in projects:
                counts[parent] = counts.get(parent, 0) + 1
                break
            if parent == source:
                break
    return counts


def declared_python(project):
    for name in ('.python-version',):
        f = project / name
        if f.is_file() and (m := re.match(r'\s*(\d+\.\d+)', f.read_text())):
            return m.group(1)
    f = project / 'pyproject.toml'
    if f.is_file():
        spec = tomllib.loads(f.read_text()).get('project', {}).get('requires-python', '')
        if m := re.search(r'(\d+\.\d+)', spec):
            return m.group(1)
    for parent in [project, *project.parents]:
        if source not in [parent, *parent.parents]:
            break
        for docker in sorted(parent.glob('Dockerfile*')):
            if m := re.search(r'^\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/library/)?python:(\d+\.\d+)', docker.read_text(), re.M | re.I):
                return m.group(1)
    return '3.12'


def requirement_args(project):
    args, hashed = [], {}
    for f in sorted(project.glob('requirements*.txt')):
        for number, raw in enumerate(f.read_text().splitlines(), 1):
            line = re.sub(r'\s+#.*$', '', raw).strip()
            if not line or line.startswith('#'):
                continue
            if m := re.match(r'^(?:-r|-c|--requirement|--constraint)\s*(\S+)$', line):
                target = (f.parent / m.group(1)).resolve()
                if source not in target.parents or not target.is_file():
                    raise ValueError(f'{f.relative_to(source)}:{number}: include escapes the captured source')
                continue
            if REFUSED.search(line):
                raise ValueError(f'{f.relative_to(source)}:{number}: refused (editable, VCS, URL, custom index or sdist option): {line[:60]}')
        args += ['-r', str(f)]
        hashed[str(f.relative_to(source))] = hashlib.sha256(f.read_bytes()).hexdigest()
    return args, hashed


counts = project_dirs()
if not counts:
    print('no Python project with tests; nothing to prepare')
    sys.exit(0)
project = max(counts, key=lambda p: (counts[p], -len(p.parts)))
version = declared_python(project)
if not re.fullmatch(r'\d+\.\d+', version):
    raise ValueError('Unsupported Python version declaration')
requirements, hashed = requirement_args(project)
if not requirements:
    raise ValueError(f'{project.relative_to(source)} has tests but no requirements*.txt; dependencies cannot be prepared')

env = {
    **os.environ,
    'UV_PYTHON_INSTALL_DIR': str(work / 'python'),
    'UV_CACHE_DIR': str(work / 'uv-cache'),
    'UV_NO_CONFIG': '1',
    'UV_PYTHON_DOWNLOADS': 'automatic',
    'UV_LINK_MODE': 'copy',
}
run = lambda args, timeout: subprocess.run(['uv', '--no-config', *args], cwd='/tmp', env=env, check=True, timeout=timeout)
run(['python', 'install', version], 900)
run(['venv', '--clear', '--python', version, str(venv)], 300)
# Resolve loose requirements to exact wheels first. The harness scans this set for advisories, so unpinned
# `>=` specifiers still get version-level coverage (as of review time). Resolution reads metadata only.
resolved = work / 'resolved'
resolved.mkdir(exist_ok=True)
(resolved / 'extra.in').write_text('pytest>=8\n')
run(['pip', 'compile', *requirements[1::2], str(resolved / 'extra.in'), '--python-version', version, '--only-binary', ':all:',
     '--index-url', 'https://pypi.org/simple', '--no-header', '--no-annotate', '-o', str(resolved / 'requirements.txt')], 900)
# One install call: afterwards the environment's interpreter must not run until the network is detached.
run(['pip', 'install', '--python', str(venv / 'bin/python'), '--only-binary', ':all:', '--index-url', 'https://pypi.org/simple',
     '-r', str(resolved / 'requirements.txt')], 1200)
(venv / 'project').write_text(str(project.relative_to(source)) or '.')
(venv / 'prepared.json').write_text(json.dumps({'python': version, 'project': str(project.relative_to(source)), 'requirements': hashed}))
print(f'prepared {project.relative_to(source)} with Python {version}')
