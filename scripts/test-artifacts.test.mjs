import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { stageTestArtifacts, selectTestArtifacts } from './test-artifacts.mjs';
import { missingTestArtifact } from './scanner-evidence.mjs';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-test-artifacts-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'input'), report = path.join(root, 'report');
  fs.mkdirSync(path.join(input, 'deploy'), { recursive: true });
  fs.mkdirSync(report);
  const bytes = Buffer.alloc(64); bytes.set([0x7f, 0x45, 0x4c, 0x46]);
  const artifact = path.join(input, 'deploy/program.so');
  fs.writeFileSync(artifact, bytes);
  return { root, input, report, artifact, bytes };
}

test('explicit artifacts are frozen and source-bound without importing deployment credentials', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.input, 'deploy/program-keypair.json'), 'must not be imported');
  const manifest = stageTestArtifacts(f.input, f.report, 'a'.repeat(64));
  assert.deepEqual(manifest.files.map(file => file.path), ['deploy/program.so']);
  assert.equal(manifest.provenance, 'operator_supplied_unverified_build');
  const staged = path.join(f.report, 'harness/sandbox-run/test-artifacts/deploy');
  assert.deepEqual(fs.readdirSync(staged), ['program.so']);
  fs.writeFileSync(f.artifact, 'changed source');
  assert.deepEqual(fs.readFileSync(path.join(staged, 'program.so')), f.bytes);
  assert.equal(selectTestArtifacts(manifest, 'a'.repeat(64)).length, 1);
  assert.throws(() => selectTestArtifacts(manifest, 'b'.repeat(64)), /source binding/);
  assert.throws(() => selectTestArtifacts({ ...manifest, files: [{ path: '../outside.so', sha256: 'c'.repeat(64) }] }, 'a'.repeat(64)), /Invalid/);
});

test('an Anchor IDL is imported beside program bytes and a keypair-shaped JSON is refused', t => {
  const f = fixture(t);
  fs.mkdirSync(path.join(f.input, 'idl'));
  fs.writeFileSync(path.join(f.input, 'idl/program.json'), JSON.stringify({ address: 'x', instructions: [] }));
  const manifest = stageTestArtifacts(f.input, f.report, 'a'.repeat(64));
  assert.deepEqual(manifest.files.map(file => file.path), ['deploy/program.so', 'idl/program.json']);
  assert.equal(selectTestArtifacts(manifest, 'a'.repeat(64)).length, 2);
  const idlOnly = fixture(t);
  fs.rmSync(path.join(idlOnly.input, 'deploy'), { recursive: true });
  fs.mkdirSync(path.join(idlOnly.input, 'idl'));
  fs.writeFileSync(path.join(idlOnly.input, 'idl/program.json'), JSON.stringify([1, 2, 3]));
  assert.throws(() => stageTestArtifacts(idlOnly.input, idlOnly.report, 'a'.repeat(64)), /not an Anchor IDL/);
  fs.writeFileSync(path.join(idlOnly.input, 'idl/program.json'), JSON.stringify({ instructions: [] }));
  assert.deepEqual(stageTestArtifacts(idlOnly.input, idlOnly.report, 'a'.repeat(64)).files.map(file => file.path), ['idl/program.json']);
});

test('symlinked, hardlinked and non-ELF program artifacts are refused', t => {
  for (const mode of ['symlink', 'hardlink', 'invalid']) {
    const f = fixture(t);
    if (mode === 'invalid') fs.writeFileSync(f.artifact, 'not a program binary');
    else {
      const other = path.join(f.root, 'other.so');
      fs.renameSync(f.artifact, other);
      if (mode === 'symlink') fs.symlinkSync(other, f.artifact);
      else fs.linkSync(other, f.artifact);
    }
    assert.throws(() => stageTestArtifacts(f.input, f.report, 'a'.repeat(64)));
  }
});

test('missing compile-time program fixtures get an actionable prerequisite diagnostic', () => {
  assert.match(missingTestArtifact("error: couldn't read `/work/target/tmp/../deploy/ratpool_escrow.so`: No such file or directory (os error 2)"), /deploy\/ratpool_escrow.so.*--test-artifacts/);
  assert.equal(missingTestArtifact('error: unknown type'), null);
});
