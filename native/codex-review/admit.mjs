import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PIN, nativeIdentity, prepareNativeSource, openPrivateOutput, runGate } from './build.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.resolve(HERE, '../.cache');
const ROOT = path.resolve(HERE, '../../..');
const WORKSPACE = path.join(CACHE, `codex-${PIN}/codex-rs`);
const BINARY = path.join(CACHE, 'target/debug/freightchain-codex-review');
const RECEIPT = path.join(CACHE, 'runtime-admission.json');
export const ADMISSION_GATES = Object.freeze(['native', 'router', 'binary', 'node', 'docker']);
export function gateWasExecuted(name, text) {
  if (name === 'router') return /test result: ok\. 1 passed; 0 failed;/.test(text);
  if (name === 'native') return [
    'actual_runtime_accepts_one_bounded_review_and_rejects_reuse',
    'managed_login_and_workspace_restrictions_are_not_relaxed',
    'actual_runtime_refuses_a_fabricated_tool_request',
  ].every((test) => text.includes(`${test} ... ok`));
  if (name === 'node' || name === 'docker') return /# pass [1-9][0-9]*\b/.test(text) && /# fail 0\b/.test(text) && /# skipped 0\b/.test(text);
  return name === 'binary';
}

export function matchesAdmission(receipt, identity) {
  return receipt?.version === 1 && receipt.admission === true && receipt.sourceCommit === PIN
    && receipt.packageDigest === identity.packageDigest && receipt.recipeDigest === identity.recipeDigest
    && typeof receipt.binarySha256 === 'string' && /^[a-f0-9]{64}$/.test(receipt.binarySha256)
    && Array.isArray(receipt.gates) && receipt.gates.length === ADMISSION_GATES.length
    && ADMISSION_GATES.every((name, i) => receipt.gates[i]?.name === name && receipt.gates[i]?.passed === true);
}
const writeReceipt = (value) => {
  const fd = openPrivateOutput(RECEIPT);
  try { fs.writeFileSync(fd, JSON.stringify(value, null, 2)); } finally { fs.closeSync(fd); }
};
async function digestFile(file) {
  const digest = crypto.createHash('sha256');
  for await (const bytes of fs.createReadStream(file)) digest.update(bytes);
  return digest.digest('hex');
}

export async function admitNative() {
  // Revoke any older receipt before preparing or executing a new gate sequence.
  writeReceipt({version:1,admission:false,sourceCommit:PIN,reason:'native_admission_in_progress'});
  const { env, metadata } = prepareNativeSource();
  const node = [process.execPath, '--test', '--test-concurrency=1'];
  const scripts = path.join(ROOT, 'audit/scripts');
  // Test fixtures may use the operator's existing Docker context; this context
  // is never part of a broker environment or mounted inside a worker.
  const testEnv = {};
  for (const key of ['HOME','USER','PATH','LANG','LC_ALL','TMPDIR','DOCKER_CONTEXT','DOCKER_HOST','DOCKER_CONFIG','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH']) {
    if (typeof process.env[key] === 'string') testEnv[key] = process.env[key];
  }
  const gates = [
    ['native', ['rustup','run','stable','cargo','test','--locked','-p','freightchain-codex-review'], WORKSPACE, env],
    ['router', ['rustup','run','stable','cargo','test','--locked','-p','codex-core','--lib','tools::spec_plan::tests::allowed_tools_filter_sources_before_code_mode_and_discovery','--','--exact'], WORKSPACE, {...env,RUST_MIN_STACK:'8388608'}],
    ['binary', ['rustup','run','stable','cargo','build','--locked','-p','freightchain-codex-review','--bin','freightchain-codex-review'], WORKSPACE, env],
    ['node', [...node,'--test-reporter=tap',...fs.readdirSync(scripts).filter((name) => name.endsWith('.test.mjs')).sort().map((name) => path.join(scripts,name))], ROOT, testEnv],
    ['docker', [...node,'--test-reporter=tap',...['worker-isolation','terminal-relay','terminal-model-connector','static-cli-review','grok-docker'].map((name) => path.join(scripts,`${name}.docker.mjs`))], ROOT, testEnv],
  ];
  const results = [];
  for (const [name, argv, cwd, environment] of gates) {
    const log = path.join(CACHE, `admission-${name}.log`);
    const result = await runGate(argv, environment, cwd, log);
    const text = fs.readFileSync(log, 'utf8');
    // A Cargo selector that ran zero tests is not a passing policy gate.
    if (!gateWasExecuted(name,text)) result.passed = false;
    results.push({name,...result,logSha256:await digestFile(log)});
    if (!result.passed) {
      const receipt = {...metadata,version:1,admission:false,gates:results,reason:`native_${name}_gate_failed`};
      writeReceipt(receipt);
      return receipt;
    }
  }
  const current = prepareNativeSource().metadata;
  if (current.packageDigest !== metadata.packageDigest || current.recipeDigest !== metadata.recipeDigest || current.lockDigest !== metadata.lockDigest) throw new Error('native_inputs_changed_during_gates');
  const stat = fs.lstatSync(BINARY);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== process.getuid()) throw new Error('native_binary_rejected');
  const receipt = {...metadata,version:1,...nativeIdentity(),admission:true,binarySha256:await digestFile(BINARY),gates:results};
  writeReceipt(receipt);
  return receipt;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== '--admit') throw new Error('native_admission_usage');
    const receipt = await admitNative();
    process.stdout.write(`${JSON.stringify(receipt,null,2)}\n`);
    if (!receipt.admission) process.exitCode = 2;
  } catch (error) {
    const reason = /^native_[a-z_]+$/.test(error.message) ? error.message : 'native_admission_failed';
    process.stderr.write(`${JSON.stringify({admission:false,reason})}\n`);
    process.exitCode = 2;
  }
}
