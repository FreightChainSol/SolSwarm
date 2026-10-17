import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { writeReportFile } from './report-contract.mjs';

// Explicit operator input, kept separate from the text-only source snapshot.
// Import program bytes only; never import generated deployment keypairs.
export function stageTestArtifacts(directory, reportDir, sourceDigest) {
  const root = fs.realpathSync(directory);
  const deploy = path.join(root, 'deploy');
  if (fs.realpathSync(deploy) !== deploy || !fs.lstatSync(deploy).isDirectory()) throw new Error('Test artifacts require a regular deploy directory');
  const files = [];
  let total = 0;
  for (const name of fs.readdirSync(deploy).sort()) {
    if (!/^[a-zA-Z0-9_][a-zA-Z0-9_-]*\.so$/.test(name)) continue;
    const source = path.join(deploy, name);
    const fd = fs.openSync(source, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    let bytes;
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 64 * 1024 * 1024 || total + stat.size > 128 * 1024 * 1024 || files.length >= 64) throw new Error('Invalid or oversized test program artifact');
      bytes = fs.readFileSync(fd);
    } finally { fs.closeSync(fd); }
    // Both supported SBF architectures use ELF containers.
    if (bytes.length < 64 || !bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) throw new Error('Test program artifact is not ELF');
    total += bytes.length;
    const relative = `deploy/${name}`;
    const staged = path.join(reportDir, 'harness/sandbox-run/test-artifacts', relative);
    fs.mkdirSync(path.dirname(staged), { recursive: true });
    fs.chmodSync(path.dirname(staged), 0o755);
    fs.chmodSync(path.dirname(path.dirname(staged)), 0o755);
    fs.writeFileSync(staged, bytes, { mode: 0o644, flag: 'wx' });
    files.push({ path: relative, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length });
  }
  if (!files.length) throw new Error('No deploy/*.so test artifacts were supplied');
  const manifest = { version: 1, sourceDigest, provenance: 'operator_supplied_unverified_build', files };
  writeReportFile(reportDir, 'harness/test-artifacts.json', JSON.stringify(manifest, null, 2));
  return manifest;
}

export function selectTestArtifacts(manifest, sourceDigest) {
  if (manifest.version !== 1 || manifest.sourceDigest !== sourceDigest || manifest.provenance !== 'operator_supplied_unverified_build' || !Array.isArray(manifest.files) || !manifest.files.length || manifest.files.length > 64 || manifest.files.some(file => !/^deploy\/[a-zA-Z0-9_][a-zA-Z0-9_-]*\.so$/.test(file.path) || !/^[a-f0-9]{64}$/.test(file.sha256))) throw new Error('Invalid test artifact manifest or source binding');
  return manifest.files.map(({ path, sha256 }) => ({ path, sha256 }));
}
