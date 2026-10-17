import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { assess, copyTree, exportArtifacts, hostAllowed, ipAllowed, osvOfflineMiss, plan, programIds, render, rpcAllowed, safeRel, seedOsv, settle } from './sandbox-lib.mjs';
import { createProxy } from './sandbox-proxy.mjs';

test('a missing offline OSV database is recognized', () => {
  assert.equal(osvOfflineMiss('could not load db: no offline version of the OSV database is available'), true);
  assert.equal(osvOfflineMiss('no offline database for npm'), true);
  assert.equal(osvOfflineMiss('No issues found'), false);
});
test('common credential and key files are excluded at every depth', (t) => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-secrets-src-'));
  const dst = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-secrets-dst-'));
  t.after(() => {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(dst, { recursive: true, force: true });
  });
  fs.mkdirSync(path.join(src, 'nested'));
  for (const name of ['.npmrc', '.netrc', '.pypirc', '.git-credentials', '.envrc', 'wallet-keypair.json', 'server.key', 'cert.p12', 'cert.pfx', 'id_rsa', 'id_ed25519']) {
    fs.writeFileSync(path.join(src, 'nested', name), 'dummy fixture');
  }
  for (const name of ['.ssh', '.aws', '.docker', '.kube', 'secrets']) {
    fs.mkdirSync(path.join(src, 'nested', name));
    fs.writeFileSync(path.join(src, 'nested', name, 'config'), 'dummy fixture');
  }
  fs.writeFileSync(path.join(src, 'nested', '.env.example'), 'KEY=dummy');
  copyTree(src, dst);
  assert.deepEqual(fs.readdirSync(path.join(dst, 'nested')), ['.env.example']);
});

test('allowlist is exact hostnames and public addresses', () => {
  assert.equal(hostAllowed('index.crates.io'), true);
  assert.equal(hostAllowed('registry.npmjs.org'), true);
  assert.equal(hostAllowed('registry.yarnpkg.com'), true);
  assert.equal(hostAllowed('evil.yarnpkg.com'), false);
  assert.equal(hostAllowed('GitHub.com'), true);
  assert.equal(hostAllowed('objects.githubusercontent.com'), true);
  assert.equal(hostAllowed('github.com.evil.com'), false);
  assert.equal(hostAllowed('evil.github.com'), false);
  assert.equal(hostAllowed('crates.io.attacker.test'), false);
  assert.equal(hostAllowed('169.254.169.254'), false);
  assert.equal(hostAllowed('localhost'), false);
  assert.equal(hostAllowed('example.com'), false);
  assert.equal(ipAllowed('8.8.8.8'), true);
  assert.equal(ipAllowed('10.0.0.1'), false);
  assert.equal(ipAllowed('169.254.169.254'), false);
  assert.equal(ipAllowed('127.0.0.1'), false);
  assert.equal(ipAllowed('192.168.1.1'), false);
  assert.equal(ipAllowed('::1'), false);
});

test('safeRel rejects traversal and spaces', () => {
  assert.equal(safeRel('.'), '.');
  assert.equal(safeRel('program/Anchor.toml'.replace('/Anchor.toml', '')), 'program');
  assert.equal(safeRel('../etc'), null);
  assert.equal(safeRel('/tmp/x'), null);
  assert.equal(safeRel('program dir'), null);
});

test('a TypeScript tree with no manifests is impossible, and secrets are not copied', () => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-plan-'));
  const dst = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-copy-'));
  fs.writeFileSync(path.join(src, 'api.ts'), 'export const x = 1;\n');
  fs.writeFileSync(path.join(src, '.env'), 'SECRET=1\n');
  fs.writeFileSync(path.join(src, '.env.example'), 'SECRET=\n');
  fs.writeFileSync(path.join(src, 'id.json'), '{}\n');
  fs.mkdirSync(path.join(src, '.git'));
  fs.writeFileSync(path.join(src, '.git', 'config'), 'token\n');
  fs.symlinkSync('/etc/passwd', path.join(src, 'escape'));
  copyTree(src, dst);
  assert.equal(fs.existsSync(path.join(dst, 'api.ts')), true);
  assert.equal(fs.existsSync(path.join(dst, '.env.example')), true);
  assert.equal(fs.existsSync(path.join(dst, '.env')), false);
  assert.equal(fs.existsSync(path.join(dst, 'id.json')), false);
  assert.equal(fs.existsSync(path.join(dst, '.git')), false);
  assert.equal(fs.existsSync(path.join(dst, 'escape')), false);
  const tree = plan(src);
  const rows = new Map(assess(tree).map((row) => [row.id, row.result]));
  for (const id of ['cargo-build', 'npm-install', 'pnpm-install', 'npm-audit', 'anchor-build', 'solana-verify', 'zap']) {
    assert.equal(rows.get(id), 'impossible', id);
  }
  assert.equal(rows.get('deployed-compare'), 'impossible');
  assert.equal(rows.get('live-probe'), 'impossible');
  const md = render(assess(tree));
  assert.match(md, /\| npm install \| impossible \|/);
  assert.match(md, /No production host or RPC was contacted/);
  fs.rmSync(src, { recursive: true, force: true });
  fs.rmSync(dst, { recursive: true, force: true });
});

test('a pinned Anchor program and a yarn lock are pending', () => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-anchor-'));
  fs.mkdirSync(path.join(src, 'program'));
  fs.writeFileSync(path.join(src, 'program', 'Anchor.toml'), '[toolchain]\nanchor_version = "1.2.1"\nsolana_version = "4.1.2"\n');
  fs.writeFileSync(path.join(src, 'program', 'Cargo.toml'), '[package]\nname = "demo"\nversion = "0.1.0"\n');
  fs.writeFileSync(path.join(src, 'program', 'Cargo.lock'), '# lock\n');
  fs.writeFileSync(path.join(src, 'program', 'build.sh'), '#!/bin/bash\nanchor build\n');
  fs.writeFileSync(path.join(src, 'package.json'), '{"scripts":{"start":"node server.js"}}\n');
  fs.writeFileSync(path.join(src, 'yarn.lock'), '# yarn\n');
  const tree = plan(src);
  assert.equal(tree.anchors[0].anchorVersion, '1.2.1');
  assert.equal(tree.anchors[0].solanaVersion, '4.1.2');
  assert.equal(tree.webStart.rel, '.');
  assert.equal(tree.osvExtra.length, 0);
  const rows = new Map(assess(tree).map((row) => [row.id, row]));
  assert.equal(rows.get('anchor-build').result, 'pending');
  assert.equal(rows.get('cargo-build').result, 'pending');
  assert.equal(rows.get('build-sh').result, 'pending');
  assert.equal(rows.get('solana-verify').result, 'pending');
  assert.equal(rows.get('yarn-install').result, 'pending');
  assert.equal(rows.get('npm-audit').result, 'pending');
  assert.match(rows.get('npm-audit').detail, /yarn/);
  const settled = settle([{ id: 'cargo-build', result: 'pending', detail: 'left pending' }]);
  assert.equal(settled.find((row) => row.id === 'cargo-build').result, 'impossible');
  fs.rmSync(src, { recursive: true, force: true });
});

test('Anchor dependency discovery includes workspace program manifests', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-anchor-workspace-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'program/programs/fixture'), { recursive: true });
  fs.writeFileSync(path.join(root, 'program/Anchor.toml'), '[toolchain]\n');
  fs.writeFileSync(path.join(root, 'program/Cargo.toml'), '[workspace]\nmembers=["programs/*"]\n');
  fs.writeFileSync(path.join(root, 'program/programs/fixture/Cargo.toml'), '[dependencies]\nanchor-lang={version="1.2.0",features=["init-if-needed"]}\n');
  assert.equal(plan(root).anchors[0].anchorVersion, '1.2.0');
  assert.equal(plan(root).anchors[0].solanaVersion, null);
});

test('extra ecosystems and an rpc url are classified without contacting them', () => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-eco-'));
  fs.writeFileSync(path.join(src, 'requirements.txt'), 'requests==2.31.0\n');
  fs.writeFileSync(path.join(src, 'go.mod'), 'module example.com/seed\n\ngo 1.22\n');
  fs.mkdirSync(path.join(src, 'src'));
  fs.writeFileSync(path.join(src, 'src', 'lib.rs'), 'declare_id!("11111111111111111111111111111111");\n');
  const tree = plan(src);
  assert.deepEqual(tree.osvExtra.map((item) => item.ecosystem).sort(), ['Go', 'PyPI']);
  const rows = new Map(assess(tree).map((row) => [row.id, row]));
  assert.equal(rows.get('osv-lock').result, 'pending');
  assert.match(rows.get('osv-lock').detail, /PyPI/);
  assert.equal(rows.get('yarn-install').result, 'impossible');
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-seed-'));
  assert.equal(seedOsv(src, tree, dest), 2);
  assert.equal(fs.existsSync(path.join(dest, 'requirements.txt')), true);
  assert.equal(fs.existsSync(path.join(dest, 'src', 'lib.rs')), false);
  assert.deepEqual(programIds(src), ['11111111111111111111111111111111']);
  assert.equal(rpcAllowed('https://api.devnet.solana.com'), 'https://api.devnet.solana.com/');
  assert.equal(rpcAllowed('http://api.devnet.solana.com'), null);
  assert.equal(rpcAllowed('https://user:pass@api.devnet.solana.com'), null);
  assert.equal(rpcAllowed('https://169.254.169.254/rpc'), null);
  assert.equal(rpcAllowed('https://127.0.0.1'), null);
  fs.rmSync(src, { recursive: true, force: true });
  fs.rmSync(dest, { recursive: true, force: true });
});

test('built programs are copied into the report and keypairs are not', () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-work-'));
  const sbf = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-sbf-'));
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-files-'));
  const so = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1]);
  const put = (root, rel, body) => {
    const file = path.join(root, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, body);
  };
  put(work, 'target/deploy/prog.so', so);
  put(work, 'target/deploy/prog-keypair.json', '{}\n');
  put(work, 'target/idl/prog.json', '{"name":"prog"}\n');
  put(work, 'target/debug/deps/lib.so', so);
  put(work, 'target/release/native.so', so);
  put(work, 'src/node_modules/evil/deploy/evil.so', so);
  put(work, 'src/pkg/target/deploy/other.so', so);
  put(work, 'cargo/registry/cache/reg.so', so);
  fs.symlinkSync(path.join(work, 'target/deploy/prog.so'), path.join(work, 'target/deploy/link.so'));
  put(sbf, 'deploy/verified.so', so);
  assert.equal(exportArtifacts(work, dest, 'build'), 4);
  assert.equal(fs.existsSync(path.join(dest, 'build/target/deploy/prog.so')), true);
  assert.equal(fs.existsSync(path.join(dest, 'build/target/idl/prog.json')), true);
  assert.equal(fs.existsSync(path.join(dest, 'build/target/release/native.so')), true);
  assert.equal(fs.existsSync(path.join(dest, 'build/src/pkg/target/deploy/other.so')), true);
  assert.equal(fs.existsSync(path.join(dest, 'build/target/deploy/prog-keypair.json')), false);
  assert.equal(fs.existsSync(path.join(dest, 'build/target/debug/deps/lib.so')), false);
  assert.equal(fs.existsSync(path.join(dest, 'build/target/deploy/link.so')), false);
  assert.equal(fs.existsSync(path.join(dest, 'build/src/node_modules/evil/deploy/evil.so')), false);
  assert.equal(fs.existsSync(path.join(dest, 'build/cargo/registry/cache/reg.so')), false);
  assert.equal(exportArtifacts(sbf, dest, 'sbf'), 1);
  const manifest = JSON.parse(fs.readFileSync(path.join(dest, 'manifest.json'), 'utf8'));
  assert.equal(manifest.length, 5);
  assert.equal(manifest.some((row) => row.path === 'sbf/deploy/verified.so' && row.sha256.length === 64), true);
  fs.rmSync(work, { recursive: true, force: true });
  fs.rmSync(sbf, { recursive: true, force: true });
  fs.rmSync(dest, { recursive: true, force: true });
});

test('the proxy refuses hosts outside the allowlist', async () => {
  const server = createProxy();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const status = await new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n');
    });
    let data = '';
    socket.on('data', (buf) => { data += buf.toString(); socket.end(); });
    socket.on('error', reject);
    socket.on('close', () => resolve(data));
  });
  assert.match(status, /^HTTP\/1\.1 403/);
  const metadata = await new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write('CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254:443\r\n\r\n');
    });
    let data = '';
    socket.on('data', (buf) => { data += buf.toString(); socket.end(); });
    socket.on('error', reject);
    socket.on('close', () => resolve(data));
  });
  assert.match(metadata, /^HTTP\/1\.1 403/);
  await new Promise((resolve) => server.close(resolve));
});
