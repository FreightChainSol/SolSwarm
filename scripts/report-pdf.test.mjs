import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { printableHtml, findBrowser, convertReport, newestReportDir } from './report-pdf.mjs';

test('print copies open every disclosure once and add page setup', () => {
  const html = printableHtml('<html><head><title>t</title></head><body><details class="finding"><summary>a</summary></details><details open><summary>b</summary></details><DETAILS id="x"></DETAILS></body></html>');
  assert.equal(html.match(/<details open/gi).length, 3);
  assert.doesNotMatch(html, /open open/);
  assert.match(html, /@page \{ size: A4;[^<]*<\/style><\/head>/);
});

test('browser lookup honours CHROME_PATH, then known installs, then PATH', () => {
  assert.equal(findBrowser({ CHROME_PATH: '/custom/chrome' }, file => file === '/custom/chrome'), '/custom/chrome');
  assert.throws(() => findBrowser({ CHROME_PATH: '/missing/chrome' }, () => false), /CHROME_PATH does not exist/);
  assert.equal(findBrowser({ PATH: '/opt/a:/opt/b' }, file => file === '/opt/b/chromium'), '/opt/b/chromium');
  assert.equal(findBrowser({ PATH: '/opt/a' }, () => false), null);
});

test('conversion refuses a missing browser or a directory without pages', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-report-pdf-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.throws(() => convertReport(root, { browser: null }), /set CHROME_PATH/);
  assert.throws(() => convertReport(root, { browser: '/unused' }), /No report\.html/);
  assert.equal(newestReportDir(path.join(root, 'absent')), null);
});
