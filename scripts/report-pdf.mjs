#!/usr/bin/env node
/**
 * report-pdf.mjs
 *
 * Prints the standalone review pages of a report directory to PDF with a local headless
 * Chrome-family browser:
 *   report.html              -> report.pdf
 *   findings-by-model.html   -> findings-by-model.pdf
 *
 * The pages are self-contained (inline styles, CSP default-src 'none'), so printing loads no
 * network resources. Every collapsible section is opened in a temporary print copy so the PDF
 * carries the full findings and evidence; the report's own HTML is never modified.
 *
 * Usage:
 *   node scripts/report-pdf.mjs [report-dir]   (default: newest dir under reports/)
 *   CHROME_PATH=/path/to/chrome node scripts/report-pdf.mjs ...
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readReportText, writeReportFile } from './report-contract.mjs';

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
export const PAGES = [['report.html', 'report.pdf'], ['findings-by-model.html', 'findings-by-model.pdf']];
const PRINT_STYLE = '<style>@page { size: A4; margin: 12mm; }</style>';
const BROWSERS = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
];
const BROWSER_COMMANDS = ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge'];

export function newestReportDir(root = path.join(scriptsDir, '..', 'reports')) {
  if (!fs.existsSync(root)) return null;
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory() && fs.existsSync(path.join(root, d.name, 'report.html')))
    .map((d) => ({ dir: path.join(root, d.name), mtime: fs.statSync(path.join(root, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)[0]?.dir || null;
}

// Opens every <details> so collapsed findings and evidence panels are printed in full.
export function printableHtml(html) {
  const opened = html.replace(/<details\b(?![^>]*\sopen[\s>=])/gi, '<details open');
  return opened.includes('</head>') ? opened.replace('</head>', `${PRINT_STYLE}</head>`) : PRINT_STYLE + opened;
}

export function findBrowser(env = process.env, exists = fs.existsSync) {
  if (env.CHROME_PATH) {
    if (!exists(env.CHROME_PATH)) throw new Error(`CHROME_PATH does not exist: ${env.CHROME_PATH}`);
    return env.CHROME_PATH;
  }
  const local = BROWSERS.find((file) => exists(file));
  if (local) return local;
  for (const dir of String(env.PATH || '').split(path.delimiter).filter(Boolean)) {
    const found = BROWSER_COMMANDS.map((name) => path.join(dir, name)).find((file) => exists(file));
    if (found) return found;
  }
  return null;
}

export function printToPdf(browser, htmlFile, pdfFile, profileDir) {
  const result = spawnSync(browser, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-sync', '--mute-audio',
    `--user-data-dir=${profileDir}`, '--no-pdf-header-footer', '--run-all-compositor-stages-before-draw',
    `--print-to-pdf=${pdfFile}`, pathToFileURL(htmlFile).href,
  ], { encoding: 'utf8', timeout: 120_000, maxBuffer: 4 * 1024 * 1024 });
  const bytes = fs.existsSync(pdfFile) ? fs.readFileSync(pdfFile) : null;
  if (result.error || !bytes || bytes.subarray(0, 5).toString('latin1') !== '%PDF-') {
    const detail = result.error?.message || (result.stderr || '').trim().split('\n').slice(-3).join(' ') || `exit ${result.status}`;
    throw new Error(`Browser did not produce a PDF for ${path.basename(htmlFile)}: ${detail}`);
  }
  return bytes;
}

export function convertReport(reportDir, { browser = findBrowser() } = {}) {
  if (!browser) throw new Error('No Chrome, Chromium, Edge or Brave browser found; set CHROME_PATH to a Chrome-family executable.');
  const pages = PAGES.filter(([html]) => fs.existsSync(path.join(reportDir, html)));
  if (!pages.length) throw new Error(`No report.html in ${reportDir}; run 'npm run html' or 'audit html' first.`);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-report-pdf-'));
  try {
    return pages.map(([html, pdf]) => {
      const source = path.join(work, html);
      fs.writeFileSync(source, printableHtml(readReportText(reportDir, html)), { mode: 0o600 });
      const bytes = printToPdf(browser, source, path.join(work, pdf), path.join(work, 'profile'));
      writeReportFile(reportDir, pdf, bytes);
      return path.join(reportDir, pdf);
    });
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const reportDir = process.argv[2] || newestReportDir();
  if (!reportDir) {
    console.error('No report directory given and none with report.html found under reports/');
    process.exit(1);
  }
  try {
    for (const file of convertReport(path.resolve(reportDir))) console.log(`PDF written to ${file}`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
