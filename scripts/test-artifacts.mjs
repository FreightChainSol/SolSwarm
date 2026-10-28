import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { writeReportFile } from './report-contract.mjs';

// Explicit operator input, kept separate from the text-only source snapshot.
// Import program bytes and Anchor IDL only; never import generated deployment keypairs.
const KINDS = [
  { dir: 'deploy', name: /^[a-zA-Z0-9_][a-zA-Z0-9_-]*\.so$/, maxBytes: 64 * 1024 * 1024 },
  { dir: 'idl', name: /^[a-zA-Z0-9_][a-zA-Z0-9_-]*\.json$/, maxBytes: 8 * 1024 * 1024 },
];
export const TEST_ARTIFACT_PATH = /^(?:deploy\/[a-zA-Z0-9_][a-zA-Z0-9_-]*\.so|idl\/[a-zA-Z0-9_][a-zA-Z0-9_-]*\.json)$/;

function validArtifact(dir, bytes) {
  // Both supported SBF architectures use ELF containers.
  if (dir === 'deploy') return bytes.length >= 64 && bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  // An Anchor IDL describes instructions; anything else (keypairs are JSON arrays) is refused.
  try { const idl = JSON.parse(bytes.toString('utf8')); return !!idl && !Array.isArray(idl) && Array.isArray(idl.instructions); } catch { return false; }
}

export function stageTestArtifacts(directory, reportDir, sourceDigest) {
  const root = fs.realpathSync(directory);
  const files = [];
  let total = 0;
  for (const kind of KINDS) {
    const folder = path.join(root, kind.dir);
    if (!fs.existsSync(folder)) continue;
    if (fs.realpathSync(folder) !== folder || !fs.lstatSync(folder).isDirectory()) throw new Error(`Test artifacts require a regular ${kind.dir} directory`);
    for (const name of fs.readdirSync(folder).sort()) {
      if (!kind.name.test(name)) continue;
      const source = path.join(folder, name);
      const fd = fs.openSync(source, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      let bytes;
      try {
        const stat = fs.fstatSync(fd);
        if (!stat.isFile() || stat.nlink !== 1 || stat.size > kind.maxBytes || total + stat.size > 128 * 1024 * 1024 || files.length >= 64) throw new Error('Invalid or oversized test artifact');
        bytes = fs.readFileSync(fd);
      } finally { fs.closeSync(fd); }
      if (!validArtifact(kind.dir, bytes)) throw new Error(kind.dir === 'deploy' ? 'Test program artifact is not ELF' : 'Test IDL artifact is not an Anchor IDL');
      total += bytes.length;
      const relative = `${kind.dir}/${name}`;
      const staged = path.join(reportDir, 'harness/sandbox-run/test-artifacts', relative);
      fs.mkdirSync(path.dirname(staged), { recursive: true });
      fs.chmodSync(path.dirname(staged), 0o755);
      fs.chmodSync(path.dirname(path.dirname(staged)), 0o755);
      fs.writeFileSync(staged, bytes, { mode: 0o644, flag: 'wx' });
      files.push({ path: relative, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length });
    }
  }
  if (!files.length) throw new Error('No deploy/*.so or idl/*.json test artifacts were supplied');
  const manifest = { version: 1, sourceDigest, provenance: 'operator_supplied_unverified_build', files };
  writeReportFile(reportDir, 'harness/test-artifacts.json', JSON.stringify(manifest, null, 2));
  return manifest;
}

export function selectTestArtifacts(manifest, sourceDigest) {
  if (manifest.version !== 1 || manifest.sourceDigest !== sourceDigest || manifest.provenance !== 'operator_supplied_unverified_build' || !Array.isArray(manifest.files) || !manifest.files.length || manifest.files.length > 64 || manifest.files.some(file => !TEST_ARTIFACT_PATH.test(file.path) || !/^[a-f0-9]{64}$/.test(file.sha256))) throw new Error('Invalid test artifact manifest or source binding');
  return manifest.files.map(({ path, sha256 }) => ({ path, sha256 }));
}
