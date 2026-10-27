#!/usr/bin/env node
// Read-only lead scan for audit run. Does not build, install, or execute the target.
// A hit is a lead for an auditor, not a finding. Patterns are the greppable subset of:
//   coral-xyz/sealevel-attacks (the 11 classes Anchor's security page points at)
//   Trail of Bits instruction-introspection (crytic/building-secure-contracts solana/)
//   Ackee PDA privilege (new_with_signer) and a direct lamport write (escrow custody)
//   OWASP sinks a regex can see (injection, XSS, command exec, TLS, CORS, JWT, cookies, secrets)
// Dependency advisories: cargo-audit (RustSec, cached DB, no fetch) and npm audit --package-lock-only
// against registry.npmjs.org. Lockfile parsers only. No target scanner config is loaded.

import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scannerEvidence } from './scanner-evidence.mjs';
import { analyzeStackAndPlans, renderReviewPlansMarkdown } from './audit-plans.mjs';
import { analyseNodeDeps, analysePythonDeps, isProductionPath } from './stack-detect.mjs';

const SKIP_DIRS = new Set([
  'node_modules', 'target', 'dist', 'build', '.git', 'vendor', 'coverage', '.next',
  '__pycache__', 'harness-fixtures', '.cargo',
]);
const MAX_FILE = 512 * 1024;
const PER_PATTERN = 40;
const MAX_LOCKS = 4;
const scannerChecks = [];
let scannerOutputDir;
const missingScanner = (tool, detail, state = 'blocked') => scannerChecks.push({ tool, state, detail });
function recordScanner(tool, result, scope = '.') {
  const evidenceFile = `scanner-output-${tool}-${scannerChecks.length}.json`;
  fs.writeFileSync(path.join(scannerOutputDir, evidenceFile), JSON.stringify(result));
  const version = spawnSync(tool === 'npm-audit' ? 'npm' : tool, [tool === 'gitleaks' ? 'version' : '--version'], { encoding: 'utf8', timeout: 5000 });
  let reportedVersion = (version.stdout || version.stderr || '').trim().slice(0, 200);
  if (tool === 'semgrep') { try { reportedVersion = JSON.parse(result.stdout).version || reportedVersion; } catch { /* invalid output remains a failed scan */ } }
  const row = { ...scannerEvidence(tool, result), version: reportedVersion, scope, evidenceFile: `harness/${evidenceFile}` };
  scannerChecks.push(row);
  return row.state !== 'failed';
}

const SOLANA_PATTERNS = [
  { id: 'unchecked-account', cls: 'sealevel 2/5 opt-out', re: /\bUncheckedAccount\b/g,
    note: 'Anchor does not check owner, signer, or program id. Read the constraint or the manual check.' },
  { id: 'account-info', cls: 'sealevel 2 owner', re: /\bAccountInfo\b/g,
    note: 'Raw account. Owner and type are not checked unless the next lines do it.' },
  { id: 'try-from-slice', cls: 'sealevel 2/3', re: /\btry_from_slice\b|\btry_deserialize\b/g,
    note: 'Deserialise only after an owner check. A shared layout is type cosplay.' },
  { id: 'init-if-needed', cls: 'sealevel 4 init', re: /\binit_if_needed\b/g,
    note: 'Re-inits a closed account. Confirm an already-live account cannot reset authority.' },
  { id: 'create-program-address', cls: 'sealevel 7 bump', re: /\bcreate_program_address\b/g,
    note: 'Admits a non-canonical bump. find_program_address, or Anchor seeds + stored bump, is the canonical form.' },
  { id: 'raw-invoke', cls: 'sealevel 5 CPI', re: /\binvoke(?:_signed)?\s*\(/g,
    note: 'Confirm the program id is a fixed Program<> or an equality check, not a caller account.' },
  { id: 'remaining-accounts', cls: 'sealevel 5 CPI', re: /\bremaining_accounts\b/g,
    note: 'Often an extra CPI target. Confirm every program id in the slice.' },
  { id: 'unchecked-introspection', cls: 'ToB introspection', re: /\bload_(?:instruction_at|current_index)(?!_checked)\s*\(/g,
    note: 'Absolute index. The _checked form and a relative index are the fix.' },
  { id: 'close-account', cls: 'sealevel 9 close', re: /\bclose\s*=/g,
    note: 'Lamports destination must be constrained. Data must be wiped so the account cannot revive.' },
  { id: 'pda-signer-cpi', cls: 'Ackee PDA privilege', re: /\bnew_with_signer\b/g,
    note: 'This PDA signs a CPI. The program id must be fixed. A caller-chosen program receives the PDA as a signer.' },
  { id: 'token-transfer-unchecked', cls: 'Token-2022 / mint binding', re: /\btoken(?:_interface)?::transfer\s*\(/g,
    note: 'transfer (not transfer_checked) does not bind the mint or decimals and ignores Token-2022 extensions (transfer fee, hook). Confirm the mint is pinned.' },
  { id: 'unchecked-arith', cls: 'arithmetic', re: /\bwrapping_(?:add|sub|mul)\s*\(|\bunchecked_(?:add|sub|mul)\s*\(/g,
    note: 'Wraps silently. Confirm this is intended and cannot be reached with attacker-chosen amounts.' },
  { id: 'lossy-cast', cls: 'arithmetic', re: /\bas\s+(?:u8|u16|u32|i8|i16|i32)\b/g,
    note: 'Narrowing cast truncates. Confirm the value is range-checked first.' },
  { id: 'panic-path', cls: 'availability', re: /\.unwrap\s*\(\s*\)|\.expect\s*\(|\bpanic!\s*\(/g,
    note: 'Panics abort the instruction. A finding when attacker-supplied state or accounts can trigger it and block settlement, refund or close.' },
  { id: 'realloc', cls: 'account size', re: /\brealloc(?:::\w+)?\s*[(=]/g,
    note: 'Resizing. Confirm payer, rent floor, zero-init and that shrinking cannot leave stale data.' },
  { id: 'set-authority', cls: 'authority', re: /\bset_authority\s*\(|\bAuthorityType::|\bset_upgrade_authority\b/g,
    note: 'Authority change. Confirm the caller is the current authority and the new authority cannot be attacker-chosen.' },
  { id: 'system-transfer', cls: 'escrow lamports', re: /\bsystem_program::transfer\s*\(|\bsystem_instruction::transfer\b/g,
    note: 'SOL custody movement. Confirm source signer/PDA, destination binding and amount source.' },
  { id: 'clock-time', cls: 'timing', re: /\bClock::get\s*\(|\bunix_timestamp\b/g,
    note: 'Deadline logic uses cluster time. Confirm boundaries (<, <=), skew tolerance and who may move deadlines.' },
  { id: 'check-comment', cls: 'sealevel 2/5 opt-out', re: /\/\/\/\s*CHECK:/g,
    note: 'Justification for an unchecked account. Verify the stated reason is true in the handler.' },
  { id: 'direct-lamports', cls: 'escrow lamports',
    re: /\b(?:try_)?borrow_mut_lamports\b|\.lamports\s*\.\s*borrow_mut\s*\(/g,
    note: 'Direct lamport edit (try_borrow_mut_lamports or .lamports.borrow_mut). Confirm the account is program-owned, the rent floor holds, and this is not a second close.' },
];

const WEB_PATTERNS = [
  { id: 'xss-html', surface: 'S6', re: /\.innerHTML\s*=|\.outerHTML\s*=|\binsertAdjacentHTML\s*\(|\bdocument\.write\s*\(/g,
    note: 'Sink. A finding only when data the attacker influences reaches it.' },
  { id: 'command-exec', surface: 'S2', re: /\bexec(?:Sync)?\s*\(\s*[`'"]/g,
    note: 'Shell string, not an argv array. Confirm the string contains request data.' },
  { id: 'sql-template', surface: 'S2', re: /\.(?:query|execute|raw)\s*\(\s*`[^`]*\$\{/g,
    note: 'Interpolated query. A bound parameter is the fix.' },
  { id: 'eval', surface: 'S2', re: /\beval\s*\(|\bnew\s+Function\s*\(/g,
    note: 'Dynamic code. Confirm the argument is not request or message data.' },
  { id: 'yaml-load', surface: 'S2', re: /\byaml\.load\s*\(/g,
    note: 'Unsafe loader. safe_load / SafeLoader is the fix.' },
  { id: 'pickle-loads', surface: 'S2', re: /\bpickle\.loads?\s*\(/g,
    note: 'Deserialising a pickle is code execution.' },
  { id: 'tls-verify-off', surface: 'S4', re: /\brejectUnauthorized\s*:\s*false\b|\bverify\s*=\s*False\b/g,
    note: 'TLS verification disabled.' },
  { id: 'cors-star', surface: 'S6', re: /origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]/g,
    note: 'Every origin. Dangerous together with credentialed cookies.' },
  { id: 'jwt-none', surface: 'S1', re: /algorithms\s*:\s*\[[^\]]*['"]none['"]/g,
    note: 'JWT none algorithm enabled.' },
  { id: 'jwt-decode', surface: 'S1', re: /\bjwt\.decode\s*\(/g,
    note: 'Decode does not check a signature. A finding only when the result authorises a request.' },
  { id: 'message-listener', surface: 'S6', re: /addEventListener\s*\(\s*['"]message['"]/g,
    note: 'Confirm event.origin is checked before the payload is trusted.' },
  { id: 'postmessage', surface: 'S6', re: /\bpostMessage\s*\(/g,
    note: 'Confirm the target origin is not *.' },
  { id: 'private-key', surface: 'S4', re: /-----BEGIN (?:RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----/g,
    note: 'Private key material in the tree.' },
  { id: 'aws-key', surface: 'S4', re: /\bAKIA[0-9A-Z]{16}\b/g,
    note: 'AWS access key id shape.' },
  { id: 'github-token', surface: 'S4', re: /\bghp_[A-Za-z0-9]{36}\b/g,
    note: 'GitHub personal access token shape.' },
  { id: 'ssrf-fetch', surface: 'S2', re: /\b(?:fetch|axios\.(?:get|post)|requests\.(?:get|post)|http\.get)\s*\([^)\n]{0,80}\b(?:req|request|params|query)\b/g,
    note: 'Request data in a URL. Confirm the host is allow-listed before the fetch.' },
  { id: 'path-from-request', surface: 'S2', re: /\bpath\.(?:join|resolve)\s*\([^)]*\breq\./g,
    note: 'Request data in a filesystem path. Confirm it cannot escape the intended directory.' },
  { id: 'open-redirect', surface: 'S2', re: /\bredirect\s*\(\s*req\./g,
    note: 'Request data as a redirect target.' },
];

// Python lead patterns. Application code only; tests are read through the existing-test catalog.
const PY_PATTERNS = [
  { id: 'py-sql-format', surface: 'S2', re: /\b(?:execute|executemany|exec_driver_sql|raw|text)\s*\(\s*(?:f["']|["'][^"'\n]*["']\s*(?:%\s|\.format\s*\())/g,
    note: 'SQL built by f-string, % or .format. Bound parameters are the fix; confirm the interpolated value is not request data.' },
  { id: 'py-orm-raw', surface: 'S2', re: /\.extra\s*\(|\bRawSQL\s*\(|\.objects\.raw\s*\(|\.order_by\s*\(\s*(?:request|params|query)/g,
    note: 'Django ORM escape hatch or request-controlled ordering. Confirm column names are allow-listed.' },
  { id: 'py-shell-exec', surface: 'S2', re: /\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)\n]*shell\s*=\s*True|\bos\.(?:system|popen)\s*\(/g,
    note: 'Shell string execution. A finding only when request, file or message data reaches the command.' },
  { id: 'py-unsafe-deserialize', surface: 'S2', re: /\b(?:marshal|dill|shelve|jsonpickle)\.(?:loads?|open|decode)\s*\(|\bpandas\.read_pickle\s*\(|\bpd\.read_pickle\s*\(|\btorch\.load\s*\(/g,
    note: 'Deserialising untrusted bytes is code execution. Confirm the source is server-trusted storage.' },
  { id: 'py-xml-parser', surface: 'S2', re: /^\s*(?:import|from)\s+(?:xml\.(?:etree|dom|sax)|lxml)\b/gm,
    note: 'Stdlib/lxml XML parser. Confirm defusedxml or entity resolution is disabled for untrusted XML.' },
  { id: 'py-mass-assignment', surface: 'S2', re: /\*\*\s*\w*(?:payload|body|data|params|request)\w*\.(?:dict|model_dump)\s*\(\s*\)|\bsetattr\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)/g,
    note: 'Request model spread into an ORM object or setattr loop. Confirm role/owner/balance fields cannot be set by the caller.' },
  { id: 'py-ssrf', surface: 'S2', re: /\b(?:httpx\.(?:get|post|put|request|stream)|requests\.(?:get|post|put|request)|urlopen|session\.(?:get|post)|client\.(?:get|post))\s*\(\s*(?:f["']|\w*(?:url|uri|host)\w*\b)/g,
    note: 'Outbound request to a computed URL. Confirm scheme/host are allow-listed and redirects/private ranges are refused.' },
  { id: 'py-file-path', surface: 'S2', re: /\b(?:send_file|send_from_directory|FileResponse|StaticFiles)\s*\(|\bopen\s*\(\s*f["']/g,
    note: 'File path built from a variable. Confirm the resolved path stays inside the intended directory.' },
  { id: 'py-template-xss', surface: 'S6', re: /\brender_template_string\s*\(|autoescape\s*=\s*False|\|\s*safe\b|\bMarkup\s*\(|\bmark_safe\s*\(/g,
    note: 'Autoescape bypass or template from a string. A finding only when attacker data reaches the template.' },
  { id: 'py-cors', surface: 'S6', re: /allow_origins\s*=\s*\[\s*["']\*["']|allow_origin_regex\s*=\s*["']\.\*|CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True/g,
    note: 'Every origin. Dangerous together with allow_credentials=True or cookie auth.' },
  { id: 'py-debug-config', surface: 'S4', re: /^\s*DEBUG\s*=\s*True\b|ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']|\.run\s*\([^)\n]*debug\s*=\s*True/gm,
    note: 'Debug mode or wildcard host. Confirm production settings override this.' },
  { id: 'py-hardcoded-secret', surface: 'S4', re: /\b(?:SECRET_KEY|JWT_SECRET|API_KEY|PRIVATE_KEY|PASSWORD|TOKEN)\w*\s*(?::\s*str\s*)?=\s*["'][^"'\n]{6,}["']/g,
    note: 'Literal secret or default. A default that production would silently accept is a finding.' },
  { id: 'py-jwt-unverified', surface: 'S1', re: /verify_signature["']?\s*:\s*False|\bjwt\.get_unverified_(?:claims|header)\s*\(|verify_(?:exp|aud)["']?\s*:\s*False|\bjwt\.decode\s*\([^)\n]*verify\s*=\s*False/g,
    note: 'Token claims read without signature or expiry verification. A finding when the result authorises a request.' },
  { id: 'py-tls-context', surface: 'S4', re: /\bssl\._create_unverified_context\b|\bCERT_NONE\b|check_hostname\s*=\s*False/g,
    note: 'TLS verification disabled.' },
  { id: 'py-weak-hash', surface: 'S1', re: /\bhashlib\.(?:md5|sha1)\s*\(/g,
    note: 'Weak hash. A finding only when used for passwords, tokens, signatures or integrity of untrusted data.' },
  { id: 'py-insecure-random', surface: 'S1', re: /\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|seed)\s*\(/g,
    note: 'Non-cryptographic PRNG. A finding when it generates tokens, nonces, challenges, seeds or prize outcomes.' },
  { id: 'py-error-leak', surface: 'S4', re: /HTTPException\s*\([^)\n]*detail\s*=\s*(?:str\s*\(\s*\w+\s*\)|f["'][^"'\n]*\{\w*(?:exc|err|e)\b)|\btraceback\.format_exc\s*\(/g,
    note: 'Exception text returned to the caller. Confirm no internal path, query or secret is exposed.' },
  { id: 'py-log-secret', surface: 'S4', re: /\b(?:logger|logging|log)\.(?:debug|info|warning|error|exception)\s*\([^)\n]*(?:token|secret|password|private_key|authorization)/gi,
    note: 'Sensitive field name in a log call. Confirm the value itself is not logged.' },
  { id: 'py-async-shared-state', surface: 'S3', re: /^\s*global\s+\w+|\basyncio\.create_task\s*\(|\bloop\.create_task\s*\(|\bensure_future\s*\(/gm,
    note: 'Shared mutable state or fire-and-forget task. Confirm check-then-act sequences are atomic and failures are handled.' },
  { id: 'py-money-float', surface: 'S3', re: /\b(?:amount|balance|price|credits?|payout|fee|stake)\w*\s*=\s*float\s*\(|\bfloat\s*\(\s*\w*(?:amount|balance|price|payout|fee)\w*/gi,
    note: 'Binary float in a money path. Decimal or integer minor units are the fix.' },
];

const NODE_PATTERNS = [
  { id: 'node-proto-pollution', surface: 'S2', re: /\b(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep|set|setWith)\s*\([^)\n]*\b(?:req|body|query|params|input|payload)\b|\bObject\.assign\s*\(\s*[\w.]+\s*,\s*req\.|__proto__/g,
    note: 'Deep merge or assign of request data. Confirm prototype keys are rejected and the target is not shared state.' },
  { id: 'node-shell-option', surface: 'S2', re: /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\([^)\n]*shell\s*:\s*true/g,
    note: 'Shell enabled on a spawn. Arguments are then parsed by a shell.' },
  { id: 'node-vm', surface: 'S2', re: /\bvm\.(?:runIn\w+|Script|compileFunction)\b|\bnew\s+vm\.Script\b/g,
    note: 'The vm module is not a sandbox. Confirm no untrusted code or template reaches it.' },
  { id: 'node-nosql', surface: 'S2', re: /\$where\b|\.(?:find|findOne|findOneAndUpdate|deleteOne|deleteMany|updateOne|updateMany)\s*\(\s*req\.(?:body|query)/g,
    note: 'Request object used as a query. Operator injection ($ne, $gt, $where) unless the shape is validated.' },
  { id: 'node-regex-input', surface: 'S2', re: /\bnew\s+RegExp\s*\(\s*(?:req\.|\w*(?:query|body|param|input)\w*)/g,
    note: 'Regex built from input. ReDoS or filter bypass unless escaped and bounded.' },
  { id: 'node-file-from-request', surface: 'S2', re: /\bres\.(?:sendFile|download)\s*\([^)\n]*\breq\.|\bfs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink)\s*\([^)\n]*\breq\./g,
    note: 'Request data in a file path. Confirm the resolved path stays inside the intended directory.' },
  { id: 'node-jwt-weak', surface: 'S1', re: /ignoreExpiration\s*:\s*true|\bjwt\.verify\s*\(\s*[^,)\n]+,\s*[^,)\n]+\s*\)/g,
    note: 'jwt.verify without an options object leaves algorithms unpinned, or expiry is ignored.' },
  { id: 'node-insecure-random', surface: 'S1', re: /\bMath\.random\s*\(/g,
    note: 'Not cryptographically secure. A finding when it generates tokens, nonces, seeds or prize outcomes.' },
  { id: 'node-weak-crypto', surface: 'S1', re: /\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]|\bcreateCipher\s*\(/g,
    note: 'Weak hash or deprecated cipher API. A finding for passwords, signatures or integrity of untrusted data.' },
  { id: 'node-tls-env', surface: 'S4', re: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/g,
    note: 'Disables TLS verification process-wide.' },
  { id: 'node-trust-proxy', surface: 'S4', re: /['"]trust proxy['"]\s*,\s*true/g,
    note: 'Trusts every X-Forwarded-For hop. Confirm rate limits and IP allow-lists cannot be spoofed.' },
  { id: 'node-cors-reflect', surface: 'S6', re: /\borigin\s*:\s*true\b|\borigin\s*:\s*(?:req|request)\.headers\.origin/g,
    note: 'Reflects any origin. Dangerous together with credentials: true.' },
  { id: 'node-react-html', surface: 'S6', re: /\bdangerouslySetInnerHTML\b|\bv-html\b|\bbypassSecurityTrust\w+|\[innerHTML\]/g,
    note: 'Framework HTML sink. A finding only when attacker-influenced data reaches it unsanitised.' },
  { id: 'node-token-storage', surface: 'S6', re: /\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"][^'"]*(?:token|jwt|session|secret|private)/gi,
    note: 'Credential in web storage is readable by any script on the origin (XSS impact).' },
  { id: 'node-secret-fallback', surface: 'S4', re: /process\.env\.\w*(?:SECRET|KEY|TOKEN|PASSWORD)\w*\s*(?:\|\||\?\?)\s*['"][^'"\n]{3,}['"]/g,
    note: 'Literal fallback for a secret. Production silently accepts the default if the variable is missing.' },
  { id: 'node-public-env', surface: 'S4', re: /\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_\w*(?:SECRET|PRIVATE_KEY|PASSWORD)\w*/g,
    note: 'Public build-time variable name suggests a secret shipped to the browser bundle.' },
];

const CONFIG_PATTERNS = [
  { id: 'eol-runtime', cls: 'S5 runtime', re: /\bFROM\s+(?:--platform=\S+\s+)?(?:docker\.io\/library\/)?(?:node:(?:1\d|20)\b|python:(?:2|3\.(?:[0-9]|10))\b)|\bnode-version:\s*['"]?(?:1\d|20)\b|\bpython-version:\s*['"]?3\.(?:[0-9]|10)\b/g,
    note: 'End-of-life Node (<=20) or Python (<=3.10) runtime. No security patches; update the base image or CI matrix.' },
  { id: 'pr-target', cls: 'S5 CI', re: /\bpull_request_target\b/g,
    note: 'A pull request can reach this workflow. Confirm it does not check out the PR head with secrets in the environment.' },
  { id: 'unpinned-action', cls: 'S5 CI', re: /uses:\s*[^\s@]+@(?:main|master|HEAD)\b/g,
    note: 'Action is not pinned to a commit. A moving tag can change what the workflow runs.' },
  { id: 'curl-pipe-sh', cls: 'S5 CI', re: /\bcurl\b[^|\n]{0,120}\|\s*(?:ba)?sh\b/g,
    note: 'Piped installer. Whatever the URL returns is executed.' },
  { id: 'docker-privileged', cls: 'S4 container', re: /\bprivileged\s*:\s*true\b|--privileged\b/g,
    note: 'Privileged container. Confirm it is not reachable from untrusted input.' },
  { id: 'docker-sock', cls: 'S4 container', re: /docker\.sock\b/g,
    note: 'Docker socket mounted. That is root on the host.' },
];

const WEB_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.go', '.php', '.rb', '.java', '.kt']);

function parseArgs(argv) {
  const out = { target: '', outDir: '', noDeps: false, selfTest: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--target') out.target = argv[++i] || '';
    else if (a === '--out') out.outDir = argv[++i] || '';
    else if (a === '--no-deps') out.noDeps = true;
    else if (a === '--self-test') out.selfTest = true;
    else throw new Error(`harness: unknown option ${a}`);
  }
  return out;
}

function walk(root, onFile) {
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        stack.push(full);
      } else if (ent.isFile()) onFile(full);
    }
  }
}

function rel(root, file) { return path.relative(root, file).split(path.sep).join('/'); }

function readText(file) {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size > MAX_FILE || st.size === 0) return null;
    return fs.readFileSync(file, 'utf8');
  } catch { return null; }
}

function hits(text, re) {
  const out = [];
  const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`;
  const r = new RegExp(re.source, flags);
  let m;
  while ((m = r.exec(text))) {
    const line = text.slice(0, m.index).split('\n').length;
    out.push(line);
    if (out.length > PER_PATTERN) break;
  }
  return out;
}

function cookieLeads(text) {
  const r = /\.cookie\s*\(|\bsetCookie\s*\(|Set-Cookie/g;
  const out = [];
  let m;
  while ((m = r.exec(text))) {
    const window = text.slice(m.index, m.index + 240);
    if (!/httpOnly|httponly/.test(window)) out.push(text.slice(0, m.index).split('\n').length);
    if (out.length > PER_PATTERN) break;
  }
  return out;
}

function collect(root, wantExt, patterns, extra) {
  const found = new Map(patterns.map((p) => [p.id, []]));
  if (extra) found.set(extra.id, []);
  let files = 0;
  walk(root, (file) => {
    const ext = path.extname(file);
    if (wantExt && !wantExt(file, ext)) return;
    const text = readText(file);
    if (text == null || text.includes('\0')) return;
    files++;
    const name = rel(root, file);
    for (const p of patterns) {
      const lines = hits(text, p.re);
      const bucket = found.get(p.id);
      for (const line of lines) {
        if (bucket.length >= PER_PATTERN) break;
        bucket.push(`${name}:${line}`);
      }
    }
    if (extra) {
      const bucket = found.get(extra.id);
      for (const line of extra.scan(text)) {
        if (bucket.length >= PER_PATTERN) break;
        bucket.push(`${name}:${line}`);
      }
    }
  });
  return { files, found };
}

function solanaStack(root) {
  const marks = [];
  walk(root, (file) => {
    const base = path.basename(file);
    if (base === 'Anchor.toml') marks.push(rel(root, file));
    else if (base === 'Cargo.toml') {
      const text = readText(file);
      if (text && /anchor-lang|solana-program|solana-sdk|pinocchio/.test(text)) marks.push(rel(root, file));
    }
  });
  return marks.slice(0, 20);
}

function section(patterns, found) {
  const lines = [];
  let total = 0;
  for (const p of patterns) {
    const rows = found.get(p.id) || [];
    total += rows.length;
    lines.push(`## ${p.id} (${p.cls || p.surface})`);
    lines.push(p.note);
    if (!rows.length) lines.push('no hit');
    else for (const row of rows) lines.push(`- ${row}`);
    lines.push('');
  }
  return { total, body: lines.join('\n') };
}

function runCmd(bin, args, cwd, timeoutMs, env) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let child;
    try {
      child = spawn(bin, args, { cwd, env, timeout: timeoutMs, killSignal: 'SIGKILL' });
    } catch (err) {
      resolve({ code: 127, stdout: '', stderr: String(err) });
      return;
    }
    child.stdout?.on('data', (b) => { if (stdout.length < 32 * 1024 * 1024) stdout += b; });
    child.stderr?.on('data', (b) => { if (stderr.length < 1024 * 1024) stderr += b; });
    child.on('error', (err) => resolve({ code: 127, stdout, stderr: `${stderr}${err.message}` }));
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

function findLocks(root, name) {
  const out = [];
  walk(root, (file) => {
    if (path.basename(file) === name && out.length < MAX_LOCKS) out.push(file);
  });
  return out;
}

async function depScan(root) {
  const lines = ['# Dependency leads', '', 'Advisories only. A vulnerable crate is a finding when the program or the server can reach it.', ''];
  const cargo = findLocks(root, 'Cargo.lock');
  const npm = findLocks(root, 'package-lock.json');
  const other = [];
  for (const name of ['pnpm-lock.yaml', 'yarn.lock', 'go.sum']) {
    if (findLocks(root, name).length) other.push(name);
  }
  const cargoHome = process.env.CARGO_HOME || path.join(process.env.HOME || '', '.cargo');
  if (!cargo.length) { lines.push('cargo-audit: no Cargo.lock'); missingScanner('cargo-audit', 'No Cargo.lock', 'not_applicable'); }
  else if (!fs.existsSync('/opt/audit-scanners/advisory-db') && !fs.existsSync(path.join(cargoHome, 'advisory-db')) && !fs.existsSync(path.join(process.env.HOME || '', '.cargo/advisory-db'))) {
    missingScanner('cargo-audit', 'RustSec database unavailable');
    lines.push('cargo-audit: RustSec DB not cached at ~/.cargo/advisory-db (no fetch on an untrusted tree). Run `cargo audit` once in a trusted repo, then re-run.');
  } else {
    for (const lock of cargo) {
      const r = await runCmd('cargo-audit', ['audit', '--file', lock, '--no-fetch', '--format', 'json', ...(fs.existsSync('/opt/audit-scanners/advisory-db') ? ['--db', '/opt/audit-scanners/advisory-db'] : [])], '/tmp', 60_000, cleanEnv());
      lines.push(`## cargo-audit ${rel(root, lock)} (exit ${r.code})`);
      lines.push(recordScanner('cargo-audit', r, rel(root, lock)) ? summariseCargo(r.stdout, r.stderr) : 'FAILED: scanner did not produce a valid advisory result.');
      lines.push('');
    }
  }
  if (!npm.length) { lines.push('npm audit: no package-lock.json'); missingScanner('npm-audit', 'No package-lock.json', 'not_applicable'); }
  else {
    // npm refuses to load one file as both user and global config, so each gets its own empty file.
    const npmConfig = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-npm-config-'));
    for (const name of ['user', 'global']) fs.writeFileSync(path.join(npmConfig, name), '', { mode: 0o600 });
    try {
      for (const lock of npm) {
        const dir = path.dirname(lock);
        const r = await runCmd('npm', [
          'audit', '--package-lock-only', '--json', '--registry', 'https://registry.npmjs.org',
          '--userconfig', path.join(npmConfig, 'user'), '--globalconfig', path.join(npmConfig, 'global'),
        ], dir, 60_000, cleanEnv({ npm_config_ignore_scripts: 'true' }));
        lines.push(`## npm audit ${rel(root, lock)} (exit ${r.code})`);
        lines.push(recordScanner('npm-audit', r, rel(root, lock)) ? summariseNpm(r.stdout, r.stderr) : 'FAILED: scanner did not produce a valid advisory result.');
        lines.push('');
      }
    } finally { fs.rmSync(npmConfig, { recursive: true, force: true }); }
  }
  reportNode(root, lines);
  await reportPython(root, lines);
  if (other.length) lines.push(`Lockfiles with no dedicated scanner in this harness: ${other.join(', ')}. osv-scanner covers these when it is on PATH (see tools.md).`);
  lines.push('This lead scan does not build, install, or send traffic. The disposable sandbox writes sandbox.md. A row there marked impossible was not covered.');
  return lines.join('\n') + '\n';
}

function reportNode(root, lines) {
  const nd = analyseNodeDeps(root);
  if (!nd.applicable) { lines.push('node-deps: no package.json'); missingScanner('node-deps', 'No package.json', 'not_applicable'); return; }
  lines.push('## node dependency resolvability');
  lines.push(`package.json files: ${nd.manifests.length}. Without a lockfile: ${nd.noLock.join(', ') || 'none'}.`);
  for (const row of nd.nonRegistry.slice(0, 20)) lines.push(`- non-registry source ${row}`);
  for (const row of nd.loose.slice(0, 20)) lines.push(`- open range ${row}`);
  for (const row of nd.lifecycle.slice(0, 20)) lines.push(`- lifecycle script ${row} (runs on install unless --ignore-scripts)`);
  if (nd.unresolved) {
    lines.push(`Coverage gap: ${nd.noLock.length} package.json without lockfile, ${nd.nonRegistry.length} non-registry source(s), ${nd.loose.length} open range(s). Advisory scans need exact locked versions.`);
    missingScanner('node-deps', `${nd.noLock.length} package.json without lockfile, ${nd.nonRegistry.length} non-registry source(s), ${nd.loose.length} open range(s): advisory coverage is partial`);
  } else {
    recordScanner('node-deps', { code: 0, stdout: JSON.stringify({ nodeDeps: { unresolved: 0, manifests: nd.manifests.length } }), stderr: '' });
    lines.push('Every dependency-bearing package.json is covered by a lockfile with registry sources.');
  }
  lines.push('');
}

async function reportPython(root, lines) {
  const py = analysePythonDeps(root);
  if (!py.applicable) { lines.push('python-deps: no Python dependency manifest'); missingScanner('python-deps', 'No Python dependency manifest', 'not_applicable'); return; }
  lines.push('## python dependency resolvability');
  lines.push(`Requirement files: ${py.requirements.join(', ') || 'none'}. Lockfiles: ${py.lockfiles.join(', ') || 'none'}. pyproject without lockfile: ${py.unlockedProjects.join(', ') || 'none'}.`);
  for (const row of [...py.unpinned.slice(0, 20)]) lines.push(`- unpinned ${row}`);
  for (const row of py.risky.slice(0, 20)) lines.push(`- non-index or editable source ${row}`);
  // The sandbox resolves loose requirements to exact wheels (uv pip compile) before reviewers start; scanning that set closes the gap as of resolution time.
  const resolved = '/work/resolved/requirements.txt';
  let resolvedScan = false;
  if (py.unresolved && fs.existsSync(resolved) && which('osv-scanner')) {
    const r = await runCmd('osv-scanner', ['scan', 'source', '--no-resolve', '--offline-vulnerabilities', '--format', 'json', '-L', `requirements.txt:${resolved}`], '/tmp', 120_000, cleanEnv());
    resolvedScan = recordScanner('osv-scanner', r, 'resolved python requirements (/work/resolved/requirements.txt)');
    lines.push(`Resolved set scan (exit ${r.code}): ${resolvedScan ? summariseOsv(r.stdout) : 'FAILED: scanner did not produce a valid advisory result.'}`);
  }
  if (py.unresolved && resolvedScan) {
    recordScanner('python-deps', { code: 0, stdout: JSON.stringify({ pythonDeps: { unresolved: py.unresolved, resolvedScan: true, requirements: py.requirements } }), stderr: '' });
    lines.push(`${py.unpinned.length} loose requirement(s) were resolved to exact versions at review time and scanned; the repository itself is still not reproducible (pin or lock them).`);
  } else if (py.unresolved) {
    lines.push(`Coverage gap: ${py.unpinned.length} unpinned requirement(s), ${py.risky.length} non-index source(s). Advisory scans (osv-scanner --no-resolve) only see exact versions; builds are not reproducible.`);
    missingScanner('python-deps', `${py.unpinned.length} unpinned requirement(s), ${py.risky.length} non-index source(s), ${py.unlockedProjects.length} pyproject without lockfile: advisory coverage is partial`);
  } else {
    recordScanner('python-deps', { code: 0, stdout: JSON.stringify({ pythonDeps: { unresolved: 0, requirements: py.requirements, lockfiles: py.lockfiles } }), stderr: '' });
    lines.push('All Python requirements are exact-pinned or locked; osv-scanner covers them.');
  }
  lines.push('');
}

function cleanEnv(extra = {}) {
  const keep = [
    'PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'CARGO_HOME', 'XDG_CACHE_HOME',
    'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy', 'NODE_USE_ENV_PROXY',
  ];
  const env = {};
  for (const k of keep) if (process.env[k]) env[k] = process.env[k];
  return { ...env, ...extra };
}

function summariseCargo(stdout, stderr) {
  try {
    const json = JSON.parse(stdout);
    const vulns = json.vulnerabilities?.list || json.vulnerabilities || [];
    const list = Array.isArray(vulns) ? vulns : [];
    if (!list.length) return 'no vulnerability in the cached RustSec DB. Warnings may still be in the raw JSON.';
    return list.slice(0, 30).map((v) => {
      const id = v.advisory?.id || v.id || 'advisory';
      const name = v.package?.name || v.package_name || '';
      return `- ${id} ${name}`.trim();
    }).join('\n');
  } catch {
    const tail = (stderr || stdout || 'no output').split('\n').slice(0, 8).join('\n');
    return `unparsed output:\n${tail}`;
  }
}

function summariseNpm(stdout, stderr) {
  try {
    const json = JSON.parse(stdout);
    const via = json.vulnerabilities || {};
    const names = Object.keys(via);
    if (!names.length) return 'no advisory at moderate or above, or the audit payload listed none.';
    return names.slice(0, 30).map((n) => `- ${n} ${via[n].severity || ''}`.trim()).join('\n');
  } catch {
    const tail = (stderr || stdout || 'no output').split('\n').slice(0, 8).join('\n');
    return `unparsed output:\n${tail}`;
  }
}

function which(bin) {
  const r = spawnSync('which', [bin], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : '';
}

function configFile(file) {
  const base = path.basename(file);
  const ext = path.extname(file);
  return ext === '.yml' || ext === '.yaml' || base === 'Dockerfile' || base.startsWith('Dockerfile.') || base.endsWith('.dockerfile');
}

function writeConfig(root) {
  const { files, found } = collect(root, (file) => configFile(file), CONFIG_PATTERNS);
  const { total, body } = section(CONFIG_PATTERNS, found);
  if (!files) return { leads: 0, files: 0, body: '# Config leads\n\nNo Dockerfile or YAML. CI and container surface absent.\n' };
  const header = [
    '# Config leads',
    '',
    'Regex leads for CI and containers. Not findings. OWASP WSTG configuration and GitHub Actions hardening.',
    `Files scanned: ${files}. Leads listed: ${total}.`,
    '',
    body,
  ];
  return { leads: total, files, body: header.join('\n') };
}

function summariseGitleaks(stdout) {
  try {
    const rows = JSON.parse(stdout);
    if (!Array.isArray(rows) || !rows.length) return 'no leak under the default rules.';
    return rows.slice(0, 30).map((row) => `- ${row.RuleID || 'rule'} ${row.File || ''}:${row.StartLine || '?'}`).join('\n');
  } catch {
    return 'unparsed output. Secrets are not copied into this file.';
  }
}

function summariseSemgrep(stdout, root) {
  try {
    const json = JSON.parse(stdout);
    const rows = json.results || [];
    const prefix = root.endsWith(path.sep) ? root : `${root}${path.sep}`;
    const warned = [...new Set((json.errors || []).map((error) => error.path || '').filter(Boolean))];
    const partial = warned.length ? `Partial parse in ${warned.length} file(s); unparsed spans were not analysed: ${warned.slice(0, 10).map((file) => file.startsWith(prefix) ? file.slice(prefix.length) : file).join(', ')}\n` : '';
    if (!rows.length) return `${partial}no result from the pinned upstream OWASP rule bundle.`;
    return partial + rows.slice(0, 40).map((row) => {
      const file = (row.path || '').startsWith(prefix) ? row.path.slice(prefix.length) : (row.path || '');
      const line = row.start?.line || '?';
      return `- ${row.check_id || 'rule'} ${file}:${line}`;
    }).join('\n');
  } catch {
    return 'unparsed output.';
  }
}

function summariseOsv(stdout) {
  try {
    const json = JSON.parse(stdout);
    const results = json.results || [];
    const lines = [];
    for (const result of results) {
      for (const pkg of result.packages || []) {
        const name = pkg.package?.name || '';
        for (const vuln of pkg.vulnerabilities || []) {
          if (lines.length < 30) lines.push(`- ${vuln.id || 'advisory'} ${name}`.trim());
        }
      }
    }
    return lines.length ? lines.join('\n') : 'no advisory.';
  } catch {
    return 'unparsed output.';
  }
}

async function gitleaksConfig() {
  if (fs.existsSync('/opt/audit-scanners/gitleaks.toml')) return '/opt/audit-scanners/gitleaks.toml';
  const ver = (spawnSync('gitleaks', ['version'], { encoding: 'utf8' }).stdout || '').trim();
  if (!/^\d+\.\d+\.\d+$/.test(ver)) return '';
  const dir = path.join(process.env.HOME || '/tmp', '.cache', 'freightchain-audit');
  const file = path.join(dir, `gitleaks-${ver}.toml`);
  if (fs.existsSync(file) && fs.statSync(file).size > 1000) return file;
  fs.mkdirSync(dir, { recursive: true });
  const url = `https://raw.githubusercontent.com/gitleaks/gitleaks/v${ver}/config/gitleaks.toml`;
  const r = await runCmd('curl', ['-fsSL', '--max-time', '30', '-o', file, url], '/tmp', 40_000, cleanEnv());
  if (r.code !== 0 || !fs.existsSync(file) || fs.statSync(file).size < 1000) {
    try { fs.rmSync(file); } catch { /* keep going without a pinned config */ }
    return '';
  }
  return file;
}

async function writeTools(root, outDir) {
  const lines = [
    '# Scanner leads',
    '',
    'Official tools only, and never the target\'s own rules or allowlist. A hit is a lead. A missing tool is not a clean result.',
    '',
  ];
  const report = path.join(outDir, 'gitleaks.json');
  if (!which('gitleaks')) { lines.push('gitleaks: not on PATH. Secret scan fell back to the regex in web.md.'); missingScanner('gitleaks', 'Executable unavailable'); }
  else {
    const config = await gitleaksConfig();
    if (!config) {
      missingScanner('gitleaks', 'Trusted rules unavailable');
      lines.push('gitleaks: not started — trusted upstream rules unavailable. Target configuration is not a fallback.');
    } else {
      const args = ['detect', '--source', root, '--no-git', '--redact=100', '--no-banner', '--ignore-gitleaks-allow', '--report-format', 'json', '--report-path', report, '--exit-code', '0', '--config', config];
      const r = await runCmd('gitleaks', args, '/tmp', 120_000, cleanEnv());
      lines.push(`## gitleaks (exit ${r.code})`);
      lines.push(`Rules: upstream gitleaks default for the installed version (${path.basename(config)}). A .gitleaks.toml in the tree is not used.`);
      const raw = fs.existsSync(report) ? fs.readFileSync(report, 'utf8') : r.stdout;
      lines.push(recordScanner('gitleaks', { ...r, stdout: raw }) ? summariseGitleaks(raw) : 'FAILED: scanner did not produce a valid secret scan result.');
      lines.push('');
    }
  }
  if (!which('semgrep')) { lines.push('semgrep: not on PATH. SAST fell back to the regex in web.md.'); missingScanner('semgrep', 'Executable unavailable'); }
  else {
    const r = await runCmd('semgrep', [
      'scan', '--metrics=off', '--disable-version-check', '--json', '--timeout=30',
      '--config=/opt/audit-scanners/semgrep-rules', '--disable-nosem', '--no-git-ignore',
      '--exclude=node_modules', '--exclude=target', '--exclude=dist', '--exclude=harness-fixtures',
      root,
    ], '/tmp', 180_000, cleanEnv({ SEMGREP_SEND_METRICS: 'off' }));
    lines.push(`## semgrep pinned upstream OWASP rules (exit ${r.code})`);
    lines.push(recordScanner('semgrep', r) ? summariseSemgrep(r.stdout, root) : 'FAILED: scanner did not produce a complete SAST result.');
    lines.push('');
  }
  if (!which('osv-scanner')) { lines.push('osv-scanner: not on PATH.'); missingScanner('osv-scanner', 'Executable unavailable'); }
  else {
    const r = await runCmd('osv-scanner', [
      'scan', 'source', '--recursive', '--no-resolve', '--allow-no-lockfiles', '--offline-vulnerabilities', '--format', 'json', root,
    ], '/tmp', 120_000, cleanEnv());
    lines.push(`## osv-scanner (exit ${r.code})`);
    lines.push('Lockfiles only (`--no-resolve`). Call analysis is off in this lead scan. The sandbox runs it when a Cargo.lock is present; see sandbox.md.');
    lines.push(recordScanner('osv-scanner', r) ? summariseOsv(r.stdout) : 'FAILED: scanner did not produce a valid advisory result.');
    lines.push('');
  }
  return lines.join('\n') + '\n';
}

// Versions in use and release-profile hardening. Latest-version comparison needs the network and is left to the reviewer.
function solanaVersions(root, marks) {
  const deps = new Map();
  let overflow = false, profile = false;
  const manifests = new Set(marks.filter((m) => m.endsWith('Cargo.toml')));
  walk(root, (file) => { if (path.basename(file) === 'Cargo.toml' && /^\s*\[workspace\]/m.test(readText(file) || '')) manifests.add(rel(root, file)); });
  for (const mark of manifests) {
    const text = readText(path.join(root, mark)) || '';
    for (const m of text.matchAll(/^\s*(anchor-lang|anchor-spl|solana-program|solana-sdk|pinocchio|spl-token(?:-2022)?)\s*=\s*(?:"([^"]+)"|\{[^}]*?version\s*=\s*"([^"]+)")/gm)) deps.set(m[1], m[2] || m[3]);
    if (/^\s*\[profile\.release\]/m.test(text)) profile = true;
    if (/overflow-checks\s*=\s*true/.test(text)) overflow = true;
  }
  const anchors = [];
  walk(root, (file) => {
    if (path.basename(file) !== 'Anchor.toml') return;
    const text = readText(file) || '';
    for (const key of ['anchor_version', 'solana_version']) { const m = text.match(new RegExp(`${key}\\s*=\\s*"([^"]+)"`)); if (m) anchors.push(`${key} ${m[1]}`); }
  });
  return [
    `Versions in use: ${[...[...deps].map(([k, v]) => `${k} ${v}`), ...anchors].join(', ') || 'none declared'}. Compare against current releases when judging known-bug exposure.`,
    overflow ? 'Release profile sets overflow-checks = true.' : `LEAD: no manifest sets overflow-checks = true${profile ? ' ([profile.release] present without it)' : ' (no [profile.release])'}. Release builds then wrap on overflow unless every operation is checked_*.`,
  ];
}

function writeSolana(root, marks) {
  if (!marks.length) {
    return { leads: 0, files: 0, body: '# Solana leads\n\nNo Anchor.toml and no Cargo.toml dependency on anchor-lang, solana-program, solana-sdk, or pinocchio. Solana surface absent.\n' };
  }
  const { files, found } = collect(root, (file, ext) => ext === '.rs' && isProductionPath(rel(root, file)), SOLANA_PATTERNS);
  const { total, body } = section(SOLANA_PATTERNS, found);
  const header = [
    '# Solana leads',
    '',
    'Regex leads only. Not findings.',
    'The OWASP Solana Programs Top 10 is unpublished (every row TBD). Do not invent S01–S10.',
    'Classes: coral-xyz/sealevel-attacks, Trail of Bits instruction introspection, Ackee account-reload / PDA-privilege / init front-run, and escrow custody when the program holds value for later release. The map onto OWASP Smart Contract Top 10 2026 is in the security-audit skill.',
    'Grep cannot close account-data matching, type cosplay, duplicate mutable accounts, PDA seed sharing, reload-after-CPI, or an escrow that pays the wrong party. Those are a source read.',
    `Stack marks: ${marks.join(', ')}`,
    ...solanaVersions(root, marks),
    `Rust files scanned: ${files}. Leads listed: ${total} (capped at ${PER_PATTERN} per pattern).`,
    '',
    body,
  ];
  return { leads: total, files, body: header.join('\n') };
}

function writePython(root, ecosystems) {
  if (ecosystems && !ecosystems.python.detected) {
    return { leads: 0, files: 0, body: '# Python leads\n\nNo production Python source. Python surface absent.\n' };
  }
  const { files, found } = collect(root, (file, ext) => ext === '.py' && isProductionPath(rel(root, file)), PY_PATTERNS);
  if (!files) return { leads: 0, files: 0, body: '# Python leads\n\nNo production Python source. Python surface absent.\n' };
  const { total, body } = section(PY_PATTERNS, found);
  const header = [
    '# Python leads',
    '',
    'Regex leads only. Not findings. Application code only (tests, docs, scripts and migrations are excluded).',
    'Grep cannot close: missing auth `Depends`, ownership checks, transaction/lock correctness, async races, or whether request data reaches a sink. Those are a source read.',
    `Python files scanned: ${files}. Leads listed: ${total} (capped at ${PER_PATTERN} per pattern).`,
    '',
    body,
  ];
  return { leads: total, files, body: header.join('\n') };
}

function writeNode(root, ecosystems) {
  const absent = '# Node leads\n\nNo production JavaScript/TypeScript source. Node surface absent.\n';
  if (ecosystems && !ecosystems.node.detected) return { leads: 0, files: 0, body: absent };
  const nodeExt = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.vue', '.svelte']);
  const { files, found } = collect(root, (file, ext) => nodeExt.has(ext) && !file.endsWith('.min.js') && isProductionPath(rel(root, file)), NODE_PATTERNS);
  if (!files) return { leads: 0, files: 0, body: absent };
  const { total, body } = section(NODE_PATTERNS, found);
  return { leads: total, files, body: ['# Node leads', '', 'Regex leads only. Not findings. Production JS/TS only (tests, docs and scripts excluded); generic sinks are also in web.md.', 'Grep cannot close: missing auth middleware, ownership checks, transaction/lock correctness or whether request data reaches a sink. Those are a source read.', `Files scanned: ${files}. Leads listed: ${total} (capped at ${PER_PATTERN} per pattern).`, '', body].join('\n') };
}

function writeWeb(root) {
  const extra = { id: 'cookie-no-httponly', surface: 'S1', note: 'Cookie setter with no httpOnly in the following 240 characters.', scan: cookieLeads };
  const { files, found } = collect(root, (file, ext) => WEB_EXT.has(ext) && !file.endsWith('.min.js'), WEB_PATTERNS, extra);
  const cookieRows = found.get(extra.id) || [];
  const shown = [...WEB_PATTERNS, { id: extra.id, cls: extra.surface, note: extra.note }];
  const { total, body } = section(shown, found);
  if (!files) {
    return { leads: 0, files: 0, body: '# Web leads\n\nNo JS, TS, Python, Go, PHP, Ruby, Java, or Kotlin sources. Web surface absent.\n' };
  }
  const header = [
    '# Web leads',
    '',
    'Regex leads only. Not findings. A sink is a finding only when attacker-controlled data reaches it.',
    'Not covered here, still required on the matching surface: IDOR, CSRF vs SameSite, races, business rules.',
    `Source files scanned: ${files}. Leads listed: ${total}. Cookie leads: ${cookieRows.length}.`,
    '',
    body,
  ];
  return { leads: total, files, body: header.join('\n') };
}

async function scan(target, outDir, noDeps) {
  const root = path.resolve(target);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`harness: not a directory: ${target}`);
  fs.mkdirSync(outDir, { recursive: true });
  scannerOutputDir = outDir;
  const marks = solanaStack(root);
  const solana = writeSolana(root, marks);
  const web = writeWeb(root);
  const config = writeConfig(root);
  const stackProfile = analyzeStackAndPlans(root);
  const python = writePython(root, stackProfile.ecosystems);
  const node = writeNode(root, stackProfile.ecosystems);
  const attackPlansMd = renderReviewPlansMarkdown(stackProfile);
  const deps = noDeps ? '# Dependency leads\n\nSkipped (--no-deps).\n' : await depScan(root);
  if (noDeps) for (const tool of ['gitleaks', 'semgrep', 'osv-scanner', 'cargo-audit', 'npm-audit', 'python-deps', 'node-deps']) missingScanner(tool, 'Skipped (--no-deps)');
  const tools = noDeps ? '# Scanner leads\n\nSkipped (--no-deps).\n' : await writeTools(root, outDir);
  fs.writeFileSync(path.join(outDir, 'scanner-results.json'), JSON.stringify({ version: 1, rustsecRevision: fs.existsSync('/opt/audit-scanners/rustsec-revision.txt') ? fs.readFileSync('/opt/audit-scanners/rustsec-revision.txt', 'utf8').trim() : null, databases: fs.existsSync('/opt/audit-scanners/databases.sha256') ? fs.readFileSync('/opt/audit-scanners/databases.sha256', 'utf8') : null, preparedAt: fs.existsSync('/opt/audit-scanners/prepared-at.txt') ? fs.readFileSync('/opt/audit-scanners/prepared-at.txt', 'utf8').trim() : null, rules: fs.existsSync('/opt/audit-scanners/rules.sha256') ? fs.readFileSync('/opt/audit-scanners/rules.sha256', 'utf8') : null, checks: scannerChecks }, null, 2));
  fs.writeFileSync(path.join(outDir, 'solana.md'), solana.body);
  fs.writeFileSync(path.join(outDir, 'web.md'), web.body);
  fs.writeFileSync(path.join(outDir, 'python.md'), python.body);
  fs.writeFileSync(path.join(outDir, 'node.md'), node.body);
  fs.writeFileSync(path.join(outDir, 'config.md'), config.body);
  fs.writeFileSync(path.join(outDir, 'deps.md'), deps);
  fs.writeFileSync(path.join(outDir, 'tools.md'), tools);
  fs.writeFileSync(path.join(outDir, 'review-plans.md'), attackPlansMd);
  fs.writeFileSync(path.join(outDir, 'stack-profile.json'), `${JSON.stringify(stackProfile, null, 2)}\n`);
  const summary = [
    '# Harness',
    '',
    `target: ${root}`,
    `detected stacks: ${stackProfile.detectedStacks.join(', ') || 'none'}`,
    `solana stack: ${marks.length ? 'yes' : 'no'} (${solana.leads} leads, ${solana.files} rust files)`,
    `python: ${stackProfile.ecosystems.python.detected ? 'yes' : 'no'} (${python.leads} leads, ${python.files} production files; frameworks: ${stackProfile.ecosystems.python.frameworks.join(', ') || 'none'}; test runner: ${stackProfile.ecosystems.python.hasPytestSignal ? 'pytest' : 'none found'})`,
    `stacks by production source: ${stackProfile.ecosystems.primary.join(', ') || 'none'}`,
    `node: ${stackProfile.ecosystems.node.detected ? 'yes' : 'no'} (${node.leads} leads, ${node.files} production files; frameworks: ${stackProfile.ecosystems.node.frameworks.join(', ') || 'none'})`,
    `web: ${web.files} source files, ${web.leads} leads`,
    `config: ${config.files} files, ${config.leads} leads`,
    `attack plans: review-plans.md (http, grpc, websockets, databases, crypto, scopes_roles, bots_economy, api_dto_abuse)`,
    `deps: ${noDeps ? 'skipped' : 'deps.md'}`,
    `scanners: ${noDeps ? 'skipped' : 'tools.md'}`,
    '',
    'Leads are not findings. Map entry points, then triage the file and review-plans.md for your surface.',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(outDir, 'summary.md'), summary);
  return { solana: solana.leads, web: web.leads, python: python.leads, node: node.leads, stacks: stackProfile.detectedStacks };
}

function selfTest() {
  const here = path.dirname(new URL(import.meta.url).pathname);
  const fx = path.join(here, 'harness-fixtures');
  const solana = writeSolana(path.join(fx, 'solana'), ['Cargo.toml']);
  const web = writeWeb(path.join(fx, 'web'));
  const config = writeConfig(path.join(fx, 'config'));
  const python = writePython(path.join(fx, 'python'));
  const nodeLeads = writeNode(path.join(fx, 'web'));
  const profile = analyzeStackAndPlans(fx);
  const plansMd = renderReviewPlansMarkdown(profile);
  const must = [
    ['unchecked-account', solana.body], ['account-info', solana.body], ['try-from-slice', solana.body],
    ['init-if-needed', solana.body], ['create-program-address', solana.body], ['raw-invoke', solana.body],
    ['remaining-accounts', solana.body], ['unchecked-introspection', solana.body], ['close-account', solana.body],
    ['pda-signer-cpi', solana.body], ['direct-lamports', solana.body],
    ...SOLANA_PATTERNS.map((p) => [p.id, solana.body]),
    ['xss-html', web.body], ['command-exec', web.body], ['sql-template', web.body], ['yaml-load', web.body],
    ['pickle-loads', web.body], ['tls-verify-off', web.body], ['cors-star', web.body], ['jwt-none', web.body],
    ['cookie-no-httponly', web.body], ['message-listener', web.body], ['postmessage', web.body], ['private-key', web.body],
    ['ssrf-fetch', web.body], ['path-from-request', web.body], ['open-redirect', web.body],
    ...PY_PATTERNS.map((p) => [p.id, python.body]),
    ...NODE_PATTERNS.map((p) => [p.id, nodeLeads.body]),
    ['eol-runtime', config.body],
    ['pr-target', config.body], ['unpinned-action', config.body], ['curl-pipe-sh', config.body],
    ['docker-privileged', config.body], ['docker-sock', config.body],
  ];
  const bad = [];
  for (const [id, body] of must) {
    const block = body.split(`## ${id} `)[1] || '';
    const until = block.split('\n## ')[0];
    if (!until.includes('bad.rs') && !until.includes('bad.js') && !until.includes('bad.py') && !until.includes('bad.yml')) bad.push(`${id}: no bad-file hit`);
    if (until.includes('good.rs') || until.includes('good.js') || until.includes('good.py') || until.includes('good.yml')) bad.push(`${id}: good file matched`);
  }
  if (!plansMd.includes('[SCOPES_ROLES]') || !plansMd.includes('[BOTS_ECONOMY]') || !plansMd.includes('[API_DTO_ABUSE]')) {
    bad.push('review-plans.md: missing cross-cutting plans');
  }
  if (solana.body.includes('find_program_address') && /create-program-address[\s\S]*good\.rs/.test(solana.body)) bad.push('canonical bump matched');
  const lamportsRe = SOLANA_PATTERNS.find((p) => p.id === 'direct-lamports').re;
  for (const sample of ['try_borrow_mut_lamports()', 'borrow_mut_lamports()', 'acc.lamports.borrow_mut()']) {
    lamportsRe.lastIndex = 0;
    if (!lamportsRe.test(sample)) bad.push(`direct-lamports: missed ${sample}`);
  }
  for (const sample of ['checked_add(1)', 'try_borrow_mut_data()', 'CpiContext::new(program, accounts)']) {
    lamportsRe.lastIndex = 0;
    if (lamportsRe.test(sample)) bad.push(`direct-lamports: over-matched ${sample}`);
  }
  if (bad.length) {
    console.error(bad.join('\n'));
    process.exit(1);
  }
  console.log(`harness self-test ok (${must.length} patterns)`);
}

const args = parseArgs(process.argv.slice(2));
if (args.selfTest) selfTest();
else if (!args.target || !args.outDir) {
  console.error('usage: harness.mjs --target <dir> --out <dir> [--no-deps] | --self-test');
  process.exit(2);
} else {
  scan(args.target, args.outDir, args.noDeps).then(
    (r) => console.log(`harness: solana leads ${r.solana}, web leads ${r.web}, python leads ${r.python}, node leads ${r.node}, stacks [${(r.stacks || []).join(',')}] -> ${args.outDir}`),
    (err) => { console.error(err.message || err); process.exit(1); },
  );
}
