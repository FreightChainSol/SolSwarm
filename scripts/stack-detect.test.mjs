import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { analyseNodeDeps, analysePythonDeps, detectEcosystems, isProductionPath } from './stack-detect.mjs';
import { analyzeStackAndPlans, renderSurfaceSkillGuidance } from './audit-plans.mjs';

function tree(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'stack-detect-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [name, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), text);
  }
  return root;
}

test('tests, docs and helper scripts do not decide the primary stack', () => {
  for (const p of ['backend/tests/test_a.py', 'frontend/scripts/check.mjs', 'docs/gen.js', 'x/conftest.py', 'web/app.test.ts']) assert.equal(isProductionPath(p), false, p);
  for (const p of ['backend/app/main.py', 'frontend/src/App.tsx']) assert.equal(isProductionPath(p), true, p);
});

test('a Python service with a Node helper script is routed as Python, with framework and declared version', t => {
  const root = tree(t, {
    'backend/requirements.txt': 'fastapi>=0.115\nsqlalchemy==2.0.48\n',
    'backend/Dockerfile': 'FROM python:3.12-slim\n',
    'backend/app/main.py': '@router.get("/x")\nasync def x(): ...\n',
    'backend/app/db.py': 'x = 1\n',
    'backend/tests/test_main.py': 'def test(): pass\n',
    'tools/scripts/build.mjs': 'export {}\n',
  });
  const eco = detectEcosystems(root);
  assert.equal(eco.python.detected, true);
  assert.equal(eco.node.detected, false);
  assert.deepEqual(eco.primary, ['python']);
  assert.deepEqual(eco.python.frameworks, ['fastapi', 'sqlalchemy']);
  assert.deepEqual(eco.python.declaredVersion, { version: '3.12', source: 'backend/Dockerfile' });
  assert.equal(eco.python.hasPytestSignal, true);
  const profile = analyzeStackAndPlans(root);
  assert.ok(profile.domains.find(d => d.id === 'http').leads[0].hits.some(h => h.citation === 'backend/app/main.py:1'), '@router.get is a route');
  const guidance = renderSurfaceSkillGuidance('S2', profile);
  assert.match(guidance, /Python: audit Pydantic/);
  assert.doesNotMatch(guidance, /Node: audit/);
  assert.doesNotMatch(guidance, /Solana\/Anchor/);
});

test('without a profile every stack is covered, and a test-only marker does not activate a domain', t => {
  assert.match(renderSurfaceSkillGuidance('S5'), /Python: audit `requirements/);
  assert.match(renderSurfaceSkillGuidance('S5'), /Node: audit/);
  const root = tree(t, { 'svc/app.py': 'x = 1\n', 'svc/tests/test_ws.py': '@app.websocket("/ws")\nasync def ws(): ...\n' });
  assert.ok(!analyzeStackAndPlans(root).detectedStacks.includes('websockets'));
});

test('unpinned and non-index Python requirements are an advisory coverage gap; pinned or locked trees are not', t => {
  const loose = analysePythonDeps(tree(t, { 'a/requirements.txt': 'fastapi>=0.1\nrequests==2.32.0\n-e git+https://x/y.git#egg=y\n# c\n' }));
  assert.equal(loose.applicable, true);
  assert.equal(loose.unpinned.length, 1);
  assert.equal(loose.risky.length, 1);
  assert.ok(loose.unresolved >= 2);
  const pinned = analysePythonDeps(tree(t, { 'b/requirements.txt': 'fastapi==0.115.0 ; python_version>"3.9"\n--hash=sha256:abc\n', 'b/poetry.lock': '' }));
  assert.equal(pinned.unresolved, 0);
  assert.equal(analysePythonDeps(tree(t, { 'c/main.js': '' })).applicable, false);
});

test('Node manifests without a lockfile, with git sources or open ranges are a coverage gap; workspace locks count', t => {
  const bad = analyseNodeDeps(tree(t, { 'a/package.json': JSON.stringify({ dependencies: { x: '*', y: 'github:o/r', z: '^1.0.0' }, scripts: { postinstall: 'node x.js' } }) }));
  assert.equal(bad.noLock.length, 1);
  assert.equal(bad.nonRegistry.length, 1);
  assert.equal(bad.loose.length, 1);
  assert.equal(bad.lifecycle.length, 1);
  assert.ok(bad.unresolved >= 3);
  const ok = analyseNodeDeps(tree(t, { 'package-lock.json': '{}', 'packages/w/package.json': JSON.stringify({ dependencies: { z: '^1.0.0' } }) }));
  assert.equal(ok.unresolved, 0);
  assert.equal(analyseNodeDeps(tree(t, { 'x/y.py': '' })).applicable, false);
});
