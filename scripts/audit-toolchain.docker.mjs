import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { EXISTING_TEST_RUNNER } from './review-workflow.mjs';
import { resolveDockerBin } from './docker-mcp-bridge.mjs';
import { stageTestArtifacts, selectTestArtifacts } from './test-artifacts.mjs';

test('provisioned Rust runs real tests offline as non-root with a read-only toolchain', { timeout: 60_000 }, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-rust-toolchain-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.chmodSync(root, 0o755);
  fs.mkdirSync(path.join(root, 'src'));
  const manifest = '[package]\nname="inert-toolchain-fixture"\nversion="0.1.0"\nedition="2021"\n';
  fs.writeFileSync(path.join(root, 'Cargo.toml'), manifest);
  fs.writeFileSync(path.join(root, 'Cargo.lock'), 'version = 3\n[[package]]\nname="inert-toolchain-fixture"\nversion="0.1.0"\n');
  fs.writeFileSync(path.join(root, 'rust-toolchain.toml'), '[toolchain]\nchannel="1.89.0"\ncomponents=["clippy","rustfmt"]\n');
  fs.writeFileSync(path.join(root, 'src/lib.rs'), '#[test]\nfn inert_existing_test() { assert_eq!(2 + 2, 4); }\n');
  const entry = { cwd: '.', command: 'cargo', args: ['test', '--locked', '--offline'], files: [{ path: 'Cargo.toml', sha256: crypto.createHash('sha256').update(manifest).digest('hex') }] };
  const result = spawnSync(resolveDockerBin(), ['run', '--interactive', '--rm', '--pull=never', '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:mode=1777', '--tmpfs', '/work:mode=1777,exec', '--env', 'CARGO_HOME=/work/cargo', '--env', 'CARGO_TARGET_DIR=/work/target', '--mount', `type=bind,src=${root},dst=/work/src,readonly`, '--entrypoint', 'node', 'audit-sandbox:local', '-e', EXISTING_TEST_RUNNER], { encoding: 'utf8', input: JSON.stringify(entry), timeout: 45_000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /test result: ok\. 1 passed; 0 failed; 0 ignored/);
  assert.doesNotMatch(result.stderr, /syncing channel|Read-only file|Downloading/);
});

test('manifest-only cache preparation executes no target build script and refuses custom sources', { timeout: 60_000 }, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-cargo-preparation-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.chmodSync(root, 0o755);
  const manifest = '[package]\nname="inert-prepare-fixture"\nversion="0.1.0"\nedition="2021"\n';
  fs.writeFileSync(path.join(root, 'Cargo.toml'), manifest);
  fs.writeFileSync(path.join(root, 'Cargo.lock'), 'version = 3\n[[package]]\nname="inert-prepare-fixture"\nversion="0.1.0"\n');
  fs.writeFileSync(path.join(root, 'build.rs'), 'fn main() { panic!("Target build scripts must never execute during fetch"); }');
  const run = () => spawnSync(resolveDockerBin(), ['run', '--rm', '--pull=never', '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:mode=1777', '--tmpfs', '/work:mode=1777', '--mount', `type=bind,src=${root},dst=/work/src,readonly`, '--entrypoint', 'python3', 'audit-sandbox:local', '/opt/prepare-cargo-cache.py'], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
  const prepared = run();
  assert.equal(prepared.status, 0, prepared.stderr);
  assert.doesNotMatch(prepared.stderr, /Compiling/);
  fs.writeFileSync(path.join(root, 'Cargo.toml'), manifest + '[dependencies]\nfixture={git="https://example.invalid/unavailable"}\n');
  const rejected = run();
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /Custom dependency sources are not prepared/);
  assert.doesNotMatch(rejected.stderr, /Updating git|Downloading/);
});

test('offline Cargo tests can load explicitly staged artifacts from CARGO_TARGET_TMPDIR', { timeout: 60_000 }, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-rust-artifact-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.chmodSync(root, 0o755);
  const source = path.join(root, 'source'), input = path.join(root, 'input'), report = path.join(root, 'report');
  for (const directory of [path.join(source, 'src'), path.join(source, 'tests'), path.join(input, 'deploy'), report]) fs.mkdirSync(directory, { recursive: true, mode: 0o755 });
  const manifest = '[package]\nname="inert-artifact-fixture"\nversion="0.1.0"\nedition="2021"\n';
  fs.writeFileSync(path.join(source, 'Cargo.toml'), manifest);
  fs.writeFileSync(path.join(source, 'Cargo.lock'), 'version = 3\n[[package]]\nname="inert-artifact-fixture"\nversion="0.1.0"\n');
  fs.writeFileSync(path.join(source, 'src/lib.rs'), '// Inert fixture.\n');
  fs.writeFileSync(path.join(source, 'tests/artifact.rs'), '#[test]\nfn existing_artifact_test(){let bytes=include_bytes!(concat!(env!("CARGO_TARGET_TMPDIR"),"/../deploy/inert.so"));assert_eq!(&bytes[..4],b"\\x7fELF");}\n');
  const bytes = Buffer.alloc(64); bytes.set([0x7f, 0x45, 0x4c, 0x46]);
  fs.writeFileSync(path.join(input, 'deploy/inert.so'), bytes);
  const staged = stageTestArtifacts(input, report, 'a'.repeat(64));
  const entry = { cwd: '.', command: 'cargo', args: ['test', '--locked', '--offline'], files: [{ path: 'Cargo.toml', sha256: crypto.createHash('sha256').update(manifest).digest('hex') }], artifacts: selectTestArtifacts(staged, 'a'.repeat(64)) };
  const run = () => spawnSync(resolveDockerBin(), ['run', '--interactive', '--rm', '--pull=never', '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:mode=1777', '--tmpfs', '/work:mode=1777,exec', '--env', 'CARGO_HOME=/work/cargo', '--env', 'CARGO_TARGET_DIR=/work/target', '--mount', `type=bind,src=${source},dst=/work/src,readonly`, '--mount', `type=bind,src=${path.join(report, 'harness/sandbox-run/test-artifacts')},dst=/out/test-artifacts,readonly`, '--entrypoint', 'node', 'audit-sandbox:local', '-e', EXISTING_TEST_RUNNER], { encoding: 'utf8', input: JSON.stringify(entry), timeout: 45_000, maxBuffer: 1024 * 1024 });
  const passed = run();
  assert.equal(passed.status, 0, passed.stderr);
  assert.match(passed.stdout, /test result: ok\. 1 passed; 0 failed; 0 ignored/);
  fs.appendFileSync(path.join(report, 'harness/sandbox-run/test-artifacts/deploy/inert.so'), 'altered');
  const changed = run();
  assert.notEqual(changed.status, 0);
  assert.match(changed.stderr, /Test artifact changed/);
});

test('offline Cargo tests automatically compile Solana SBF cdylib artifacts into deploy/*.so when unstaged', { timeout: 90_000 }, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-sbf-toolchain-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.chmodSync(root, 0o755);
  for (const directory of [path.join(root, 'src'), path.join(root, 'tests')]) fs.mkdirSync(directory, { recursive: true, mode: 0o755 });
  const manifest = '[package]\nname="inert-sbf-program"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["cdylib","lib"]\n';
  fs.writeFileSync(path.join(root, 'Anchor.toml'), '[programs.localnet]\ninert_sbf_program = "11111111111111111111111111111111"\n');
  fs.writeFileSync(path.join(root, 'Cargo.toml'), manifest);
  fs.writeFileSync(path.join(root, 'Cargo.lock'), 'version = 3\n[[package]]\nname="inert-sbf-program"\nversion="0.1.0"\n');
  fs.writeFileSync(path.join(root, 'src/lib.rs'), '#[no_mangle]\npub extern "C" fn entrypoint(_input: *mut u8) -> u64 { 0 }\n');
  fs.writeFileSync(path.join(root, 'tests/sbf.rs'), '#[test]\nfn existing_sbf_artifact_test(){let bytes=include_bytes!(concat!(env!("CARGO_TARGET_TMPDIR"),"/../deploy/inert_sbf_program.so"));assert_eq!(&bytes[..4],b"\\x7fELF");}\n');
  const entry = { cwd: '.', command: 'cargo', args: ['test', '--locked', '--offline'], timeoutMs: 900000, files: [{ path: 'Cargo.toml', sha256: crypto.createHash('sha256').update(manifest).digest('hex') }] };
  const result = spawnSync(resolveDockerBin(), ['run', '--interactive', '--rm', '--pull=never', '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:mode=1777', '--tmpfs', '/work:mode=1777,exec', '--env', 'CARGO_HOME=/work/cargo', '--env', 'CARGO_TARGET_DIR=/work/target', '--mount', `type=bind,src=${root},dst=/work/src,readonly`, '--entrypoint', 'node', 'audit-sandbox:local', '-e', EXISTING_TEST_RUNNER], { encoding: 'utf8', input: JSON.stringify(entry), timeout: 60_000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /test result: ok\. 1 passed; 0 failed; 0 ignored/);
});
