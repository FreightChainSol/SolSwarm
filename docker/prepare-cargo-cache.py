"""Fetch locked crates from a manifest-only tree; never run target builds or hooks."""
import os
from pathlib import Path
import shutil
import subprocess
import tomllib

source = Path('/work/src')
seed = Path('/work/cargo-seed')
seed.mkdir(exist_ok=True)
locks = sorted(source.rglob('Cargo.lock'))
manifests = sorted(source.rglob('Cargo.toml'))
for lock in locks:
    data = tomllib.loads(lock.read_text())
    for package in data.get('package', []):
        origin = package.get('source')
        if origin and origin != 'registry+https://github.com/rust-lang/crates.io-index':
            raise ValueError('Only locked crates.io dependencies can be prepared')
for manifest in manifests:
    data = tomllib.loads(manifest.read_text())
    def check(value):
        if isinstance(value, dict):
            if any(key in value for key in ('git', 'registry', 'registry-index')):
                raise ValueError('Custom dependency sources are not prepared')
            if isinstance(value.get('path'), str) and not (manifest.parent / value['path']).resolve().is_relative_to(source):
                raise ValueError('Dependency path escapes captured source')
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(data)
    for dependency in manifest.parent.rglob('.cargo'):
        if dependency.is_dir():
            raise ValueError('Target Cargo configuration requires separate preparation')
    target = seed / manifest.relative_to(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(manifest, target)
    if 'package' in data:
        paths = ['src/lib.rs', 'src/main.rs']
        paths += [table['path'] for key in ['lib', 'bin', 'test', 'bench', 'example'] for table in (data.get(key, []) if isinstance(data.get(key), list) else [data.get(key, {})]) if 'path' in table]
        for relative in paths:
            stub = (target.parent / relative).resolve()
            if not stub.is_relative_to(seed.resolve()):
                raise ValueError('Target manifest path escapes preparation tree')
            stub.parent.mkdir(parents=True, exist_ok=True)
            stub.write_text('// Inert fetch-only placeholder. Never compiled.\n')
for lock in locks:
    target = seed / lock.relative_to(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(lock, target)
    subprocess.run(['cargo', 'fetch', '--locked', '--manifest-path', str(target.parent / 'Cargo.toml')], cwd=seed, env={**os.environ, 'CARGO_NET_OFFLINE': 'false', 'CARGO_HOME': '/work/cargo', 'CARGO_HTTP_TIMEOUT': '30'}, check=True, timeout=600)
