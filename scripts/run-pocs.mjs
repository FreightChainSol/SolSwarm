#!/usr/bin/env node
/* The audit PoC gate. Runs every PoC listed in audit/pocs/status.json and reports, per test, whether its finding still reproduces.
   An 'open' PoC never fails the run (it documents a finding not fixed yet) – but a PoC that no longer loads does. The run exits 1 when a
   'control' test breaks, when a promoted normal-suite spec fails, or when a PoC errors. Server specs are copied next to the depth their
   imports expect (runAt) under a __poc__ prefix and removed afterwards; program PoCs run only with --program (cargo + LiteSVM, slow) and need
   a .so built from THIS tree (`npm run program:build`): a stale binary fails every test – the control tests (safe_ / probe_) then break the run.
   Usage: node audit/scripts/run-pocs.mjs [--program] [--only <substring>] */
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const POCS = join(ROOT, 'pocs');
const SERVER = join(ROOT, 'server');
const PROGRAM = join(ROOT, 'programs');
const args = process.argv.slice(2);
const withProgram = args.includes('--program');
const only = args.includes('--only') ? args[args.indexOf('--only') + 1] : null;
const { pocs } = JSON.parse(readFileSync(join(POCS, 'status.json'), 'utf8'));

const cleanup = new Set();
const removeAll = () => { for (const p of cleanup) rmSync(p, { force: true, recursive: true }); cleanup.clear(); };
process.on('exit', removeAll);
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { removeAll(); process.exit(130); });

/** → { error?: string, tests: [{ title, passed }] } */
function runVitest(specAbs) {
  const out = join(mkdtempSync(join(tmpdir(), 'poc-')), 'r.json');
  cleanup.add(dirname(out));
  spawnSync('npx', ['vitest', 'run', relative(SERVER, specAbs), '--reporter=json', `--outputFile=${out}`], { cwd: SERVER, encoding: 'utf8' });
  if (!existsSync(out)) return { error: 'vitest wrote no report', tests: [] };
  const file = JSON.parse(readFileSync(out, 'utf8')).testResults?.[0];
  if (!file) return { error: 'no test file matched (is runAt inside vitest.config include?)', tests: [] };
  const tests = file.assertionResults.map((a) => ({ title: a.fullName || a.title, passed: a.status === 'passed' }));
  return tests.length ? { tests } : { error: (file.message || 'suite failed to load').split('\n')[0], tests };
}

function runNodeTest(fileAbs) {
  const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', fileAbs], { cwd: dirname(fileAbs), encoding: 'utf8' });
  const tests = [...r.stdout.matchAll(/^(not ok|ok) \d+ - (.+)$/gm)].map((m) => ({ title: m[2], passed: m[1] === 'ok' }));
  return tests.length ? { tests } : { error: (r.stderr || r.stdout).trim().split('\n')[0] || 'no TAP output', tests };
}

function runCargo(rsAbs) {
  const name = basename(rsAbs, '.rs');
  const r = spawnSync('cargo', ['test', '--manifest-path', join(PROGRAM, 'Cargo.toml'), '--test', name, '--', '--test-threads=1'], { cwd: PROGRAM, encoding: 'utf8' });
  const tests = [...`${r.stdout}`.matchAll(/^test (\S+) \.\.\. (ok|FAILED)$/gm)].map((m) => ({ title: m[1], passed: m[2] === 'ok' }));
  return tests.length ? { tests } : { error: (r.stderr || '').trim().split('\n').slice(-1)[0] || 'cargo produced no results', tests };
}

function runPoc(poc) {
  const src = join(POCS, poc.file);
  if (poc.file.startsWith('client/')) return runNodeTest(src);
  const dir = join(ROOT, poc.runAt);
  if (poc.file.startsWith('program/')) {
    if (!withProgram) return { skipped: 'program PoCs run only with --program', tests: [] };
    const dst = join(dir, basename(src));
    if (existsSync(dst)) return { error: `${relative(ROOT, dst)} already exists – refusing to overwrite`, tests: [] };
    copyFileSync(src, dst); cleanup.add(dst);
    return runCargo(dst);
  }
  if (!existsSync(dir)) { mkdirSync(dir, { recursive: true }); cleanup.add(join(SERVER, relative(SERVER, dir).split('/').slice(0, 3).join('/'))); }
  const dst = join(dir, `__poc__${basename(src)}`);
  copyFileSync(src, dst); cleanup.add(dst);
  return runVitest(dst);
}

function runPromoted(path) {
  if (!/\.(spec\.ts|test\.mjs|rs)$/.test(path)) return { skipped: 'not a spec', tests: [] };
  const abs = join(ROOT, path);
  if (!existsSync(abs)) return { error: 'promoted spec missing', tests: [] };
  if (path.startsWith('server/')) return runVitest(abs);
  if (path.endsWith('.rs')) return withProgram ? runCargo(abs) : { skipped: 'program spec, run with --program', tests: [] };
  return runNodeTest(abs);
}

let failed = 0;
const tally = { open: 0, fixed: 0, reproduces: 0, stopped: 0 };
for (const poc of pocs.filter((p) => !only || p.file.includes(only) || p.items.includes(only))) {
  const head = `${poc.file}  [${poc.items.join(', ') || 'controls'}]  ${poc.status.toUpperCase()} (${poc.polarity})`;
  if (poc.status === 'fixed') { tally.fixed++; console.log(`\n✔ ${head} – promoted specs only`); }
  else {
    tally.open++;
    const r = runPoc(poc);
    if (r.skipped) { console.log(`\n· ${head} – ${r.skipped}`); }
    else if (r.error) { failed++; console.log(`\n✖ ${head}\n    ERROR: ${r.error}`); }
    else {
      console.log(`\n${poc.polarity === 'control' ? '◇' : '○'} ${head}${poc.note ? `\n    note: ${poc.note}` : ''}`);
      for (const t of r.tests) {
        const by = Object.entries(poc.superseded ?? {}).find(([c]) => t.title.includes(c))?.[1];
        if (by) { console.log(`    superseded    ${t.title}  →  ${by}`); continue; }
        if (poc.polarity === 'control' || poc.controls?.some((c) => t.title.includes(c))) { if (!t.passed) failed++; console.log(`    ${t.passed ? 'holds        ' : 'BROKEN       '} ${t.title}`); continue; }
        const reproduces = poc.polarity === 'secure' ? !t.passed : t.passed;
        reproduces ? tally.reproduces++ : tally.stopped++;
        console.log(`    ${reproduces ? 'reproduces   ' : 'not reproduced'} ${t.title}`);
      }
    }
  }
  for (const spec of poc.promoted) {
    const r = runPromoted(spec);
    const bad = r.error || r.tests.some((t) => !t.passed);
    if (r.skipped) console.log(`    promoted ${spec}: ${r.skipped}`);
    else { if (bad) failed++; console.log(`    promoted ${spec}: ${bad ? `REGRESSED ${r.error ?? r.tests.filter((t) => !t.passed).map((t) => t.title).join('; ')}` : 'green'}`); }
  }
}
console.log(`\n${tally.open} open PoC files (${tally.reproduces} tests reproduce, ${tally.stopped} no longer do – promote and invert those), ${tally.fixed} fixed, ${failed} failure(s).`);
process.exit(failed ? 1 : 0);
