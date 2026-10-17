import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { PIN, NATIVE_DEPENDENCIES, overlayManifest, overlayLock, withoutNativeEntry, validateOverlayFiles, validateSourceExtras, openPrivateOutput } from '../native/codex-review/build.mjs';
import { REVIEW_INSTRUCTION } from './terminal-review-contract.mjs';

test('native source pin and metadata cannot claim runtime admission', () => {
  const pin = JSON.parse(fs.readFileSync(new URL('../native/codex-review/source-pin.json', import.meta.url)));
  assert.equal(pin.commit, PIN);
  assert.equal(pin.admission, false);
  assert.equal(pin.stage, 'policy_and_contract_gates');
});
test('source inputs reject untracked and ignored files outside the exact overlay', () => {
  validateSourceExtras(['codex-rs/freightchain-review/Cargo.toml', 'codex-rs/freightchain-review/src/lib.rs']);
  for (const name of ['.cargo/config.toml', 'codex-rs/.cargo/config.toml', 'codex-rs/freightchain-review/build.rs', 'codex-rs/core/untracked.rs']) {
    assert.throws(() => validateSourceExtras([name]), /native_cached_untracked_input/);
  }
});
test('private receipts and logs refuse links without truncating targets', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'native-output-fixture-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'target');
  fs.writeFileSync(target, 'inert preserved bytes', { mode: 0o600 });
  const link = path.join(root, 'linked.json');
  fs.symlinkSync(target, link);
  assert.throws(() => openPrivateOutput(link));
  assert.equal(fs.readFileSync(target, 'utf8'), 'inert preserved bytes');
  fs.unlinkSync(link);
  fs.linkSync(target, link);
  assert.throws(() => openPrivateOutput(link), /native_output_file_rejected/);
  assert.equal(fs.readFileSync(target, 'utf8'), 'inert preserved bytes');
  const fd = openPrivateOutput(path.join(root, 'valid.json'));
  fs.writeFileSync(fd, '{"fixture":true}');
  fs.closeSync(fd);
});
test('native overlay refuses unexpected build scripts and symlinked parents', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'native-overlay-fixture-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  validateOverlayFiles(root);
  fs.writeFileSync(path.join(root, 'build.rs'), '// inert unexpected input\n');
  assert.throws(() => validateOverlayFiles(root), /native_overlay_extra_input/);
  fs.unlinkSync(path.join(root, 'build.rs'));
  fs.symlinkSync(os.tmpdir(), path.join(root, 'src'));
  assert.throws(() => validateOverlayFiles(root), /native_overlay_link_rejected/);
});
test('native and existing source-review instructions are byte-equivalent', () => {
  const instruction = fs.readFileSync(new URL('../native/codex-review/review-instruction.txt', import.meta.url), 'utf8').replace(/\n$/, '');
  assert.equal(instruction, REVIEW_INSTRUCTION);
});
test('workspace overlay is narrowly anchored and does not update dependencies', () => {
  const original = '[workspace]\nmembers = [\n    "core",\n]\n';
  const overlay = overlayManifest(original);
  assert.equal(overlay, '[workspace]\nmembers = [\n    "freightchain-review",\n    "core",\n]\n');
  assert.throws(() => overlayManifest(overlay));
  assert.throws(() => overlayManifest('different workspace'));
});
test('lock overlay only adds the native package with pinned existing versions', () => {
  const names = NATIVE_DEPENDENCIES;
  const lock = names.map((name) => `[[package]]\nname = "${name}"\nversion = "${name === 'sha2' ? '0.10.9' : '1.0.0'}"\n`).join('\n');
  const overlay = overlayLock(lock);
  assert.ok(overlay.includes('name = "codex-core"'));
  assert.ok(overlay.indexOf('name = "freightchain-codex-review"') < overlay.indexOf('name = "serde"'));
  assert.ok(overlay.includes('name = "sha2"\nversion = "0.10.9"'));
  assert.equal(overlay.split('name = "freightchain-codex-review"').length, 2);
  assert.throws(() => overlayLock(overlay));
  assert.throws(() => overlayLock('missing upstream packages'));
  assert.equal(withoutNativeEntry(overlay).trimEnd(), lock.trimEnd());
});
test('release lock reconciliation changes local labels but never external packages', () => {
  const names = NATIVE_DEPENDENCIES;
  const local = new Set(['codex-core', 'codex-extension-api', 'codex-features', 'codex-protocol', 'core_test_support']);
  const lock = names.map((name) => `[[package]]\nname = "${name}"\nversion = "${local.has(name) ? '0.0.0' : name === 'sha2' ? '0.10.9' : '1.0.0'}"\n${local.has(name) ? '' : 'source = "registry+https://example.invalid/index"\nchecksum = "fixture-checksum"\n'}`).join('\n');
  const overlay = overlayLock(lock);
  assert.ok(overlay.includes('name = "codex-core"\nversion = "0.162.1"'));
  assert.ok(overlay.includes('name = "anyhow"\nversion = "1.0.0"\nsource = "registry+https://example.invalid/index"\nchecksum = "fixture-checksum"'));
  const externalZero = lock.replace('name = "anyhow"\nversion = "1.0.0"', 'name = "anyhow"\nversion = "0.0.0"');
  assert.ok(overlayLock(externalZero).includes('name = "anyhow"\nversion = "0.0.0"\nsource = "registry+https://example.invalid/index"'));
});
