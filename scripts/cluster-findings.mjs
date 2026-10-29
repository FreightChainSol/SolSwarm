/**
 * Root-cause clustering for auditor claims.
 *
 * Two claims join one cluster when either:
 *  - exact: same surface family, identical title, and a shared citation (the original rule); or
 *  - structural: different auditors cite at least STRUCTURAL_MIN_FILES distinct files
 *    with lines within LINE_TOLERANCE of each other. Surface is ignored: public endpoints and
 *    error messages are reachable from several surfaces, so independent auditors report them twice.
 *
 * One shared file is deliberately not enough. Controllers, error mappers and config files are
 * touched by unrelated claims, and single-link merging on them chains separate issues together.
 * Same-auditor claims never merge structurally: an auditor that split two findings meant them apart.
 */

export const LINE_TOLERANCE = 3;
export const STRUCTURAL_MIN_FILES = 2;

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const rank = (s) => SEVERITY_RANK[s] ?? 2;

function parseAnchors(locations) {
  const out = [];
  for (const loc of locations || []) {
    const m = /^(.+):(\d+)$/.exec(String(loc));
    if (m) out.push({ file: m[1], line: Number(m[2]) });
  }
  return out;
}

/** Distinct files cited by both claims within `tolerance` lines of each other. */
export function sharedAnchorFiles(a, b, tolerance = LINE_TOLERANCE) {
  const shared = new Set();
  const bAnchors = parseAnchors(b.location);
  for (const x of parseAnchors(a.location)) {
    if (bAnchors.some((y) => y.file === x.file && Math.abs(y.line - x.line) <= tolerance)) shared.add(x.file);
  }
  return [...shared];
}

function exactMatch(a, b) {
  return String(a.surface).slice(0, 2) === String(b.surface).slice(0, 2)
    && a.title.toLowerCase() === b.title.toLowerCase()
    && (a.location || []).some((p) => (b.location || []).includes(p));
}

function structuralMatch(a, b) {
  return a.auditor !== b.auditor && sharedAnchorFiles(a, b).length >= STRUCTURAL_MIN_FILES;
}

/**
 * @param {Array<{title:string,surface:string,severity?:string,confidence?:string,location?:string[],auditor:string,claimId?:string}>} findings
 * @returns clusters in first-member order; each cluster's `findings`/`claimIds` start with its highest-severity claim.
 */
export function clusterFindings(findings) {
  const parent = findings.map((_, i) => i);
  const find = (i) => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
  for (let i = 0; i < findings.length; i++) {
    for (let j = i + 1; j < findings.length; j++) {
      if (find(i) !== find(j) && (exactMatch(findings[i], findings[j]) || structuralMatch(findings[i], findings[j]))) {
        parent[find(j)] = find(i);
      }
    }
  }
  const groups = new Map();
  findings.forEach((f, i) => {
    const root = find(i);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(f);
  });
  return [...groups.values()].map((members, n) => {
    // Stable sort: the highest-severity claim leads, ties keep audit order.
    const ordered = [...members].sort((a, b) => rank(b.severity) - rank(a.severity));
    const [primary] = ordered;
    const auditors = [...new Set(ordered.map((f) => f.auditor))];
    return {
      id: `CLUSTER-${n + 1}`,
      surface: primary.surface,
      primaryTitle: primary.title,
      normTitle: primary.title.toLowerCase(),
      severity: primary.severity || 'medium',
      confidence: ordered.some((f) => String(f.confidence).startsWith('confirmed')) ? 'confirmed' : primary.confidence || 'probable',
      auditors,
      claimIds: ordered.map((f) => f.claimId).filter(Boolean),
      findings: ordered,
      // Ranges of severity across merged claims, so disagreement stays visible.
      severities: [...new Set(ordered.map((f) => f.severity).filter(Boolean))],
    };
  });
}

/**
 * Cross-auditor cluster pairs that share at least one near anchor but were not merged.
 * Informational only: a single shared file is usually a shared utility, sometimes a true duplicate
 * the rules were too strict for. Surfaces them for a human or a model dedup pass.
 */
export function dedupCandidates(clusters) {
  const out = [];
  for (let i = 0; i < clusters.length; i++) {
    for (let j = i + 1; j < clusters.length; j++) {
      const shared = new Set();
      for (const a of clusters[i].findings) {
        for (const b of clusters[j].findings) {
          if (a.auditor === b.auditor) continue;
          for (const file of sharedAnchorFiles(a, b)) shared.add(file);
        }
      }
      if (shared.size) out.push({ a: clusters[i].id, b: clusters[j].id, titles: [clusters[i].primaryTitle, clusters[j].primaryTitle], sharedFiles: [...shared] });
    }
  }
  return out;
}

/**
 * Heuristic: a title listing three or more items ("A, B, and C") usually bundles several root causes.
 * Advisory only; such claims make cluster scores and peer reviews ambiguous.
 */
export function isCompoundTitle(title) {
  // Only capitalised items count; a lowercase list ("returns seed, wallet, and data") is one defect.
  return (String(title).match(/(?:,\s+(?:and\s+)?|;\s+|\s+and\s+)(?=[A-Z])/g) || []).length >= 2;
}
