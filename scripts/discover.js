#!/usr/bin/env node
// Appwrite Security — KEYLESS DISCOVER MODE.
//
// Parses the user's repo statically to find Appwrite client SDK usage:
//   - new Client().setEndpoint('...').setProject('...')
//   - new Databases(client).listDocuments(databaseId, collectionId)
//   - APPWRITE_ENDPOINT / APPWRITE_PROJECT_ID env references
// Then probes the public Appwrite REST API anonymously to confirm leaks:
//   - GET /v1/databases/{databaseId}/collections/{collectionId}/documents → returns rows? perms too open.
// No API key, no admin token.
//
// Triggered by `appwrite-security --discover [path]`

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const PATTERNS = {
  // new Databases(client).listDocuments('db_id', 'coll_id')  |  databases.listDocuments(dbId, collId, [...])
  listDocuments: /\.listDocuments\(\s*['"`]([^'"`]+)['"`]\s*,\s*['"`]([^'"`]+)['"`]/g,
  // databases.getDocument('db', 'coll', 'doc_id')
  getDocument: /\.getDocument\(\s*['"`]([^'"`]+)['"`]\s*,\s*['"`]([^'"`]+)['"`]/g,
  // Storage().listFiles('bucket_id')
  listFiles: /\.listFiles\(\s*['"`]([^'"`]+)['"`]/g,
  // .setEndpoint('https://cloud.appwrite.io/v1')
  endpoint: /\.setEndpoint\(\s*['"`](https?:\/\/[^'"`]+)['"`]\s*\)/g,
  // .setProject('xxxxxx')
  project: /\.setProject\(\s*['"`]([a-zA-Z0-9_-]+)['"`]\s*\)/g,
  // APPWRITE_ENDPOINT=https://...
  endpointEnv: /APPWRITE_ENDPOINT\s*=\s*['"`]?(https?:\/\/[^\s'"`]+)/g,
  // APPWRITE_PROJECT_ID=xxx
  projectEnv: /APPWRITE_PROJECT_ID\s*=\s*['"`]?([a-zA-Z0-9_-]+)/g,
};

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "out", ".turbo",
  "coverage", ".cache", ".vercel", "__pycache__", ".appwrite"
]);

const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
  ".env", ".env.local", ".env.example", ".env.production"
]);

function walk(dir, files = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return files; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(p, files);
    } else {
      const lower = e.name.toLowerCase();
      const hasExt = [...SCAN_EXTENSIONS].some(x => lower.endsWith(x));
      if (hasExt || lower.startsWith(".env")) files.push(p);
    }
  }
  return files;
}

function readSafe(p) { try { return readFileSync(p, "utf8"); } catch { return ""; } }

export function staticScan(root) {
  const files = walk(root);
  const out = {
    endpoint: null,
    projectId: null,
    collections: new Set(),       // Set of "databaseId/collectionId"
    buckets: new Set(),
    sourceFiles: 0,
    envFiles: 0,
    rootDir: root,
  };

  for (const file of files) {
    const content = readSafe(file);
    if (!content) continue;
    const isEnv = file.toLowerCase().includes(".env");
    if (isEnv) out.envFiles++; else out.sourceFiles++;

    if (!out.endpoint) {
      const e = PATTERNS.endpoint.exec(content);
      if (e) out.endpoint = e[1];
    }
    if (!out.endpoint && isEnv) {
      const ev = PATTERNS.endpointEnv.exec(content);
      if (ev) out.endpoint = ev[1].replace(/[\s'"`].*$/, "");
    }
    if (!out.projectId) {
      const p = PATTERNS.project.exec(content);
      if (p) out.projectId = p[1];
    }
    if (!out.projectId && isEnv) {
      const pe = PATTERNS.projectEnv.exec(content);
      if (pe) out.projectId = pe[1].replace(/[\s'"`].*$/, "");
    }

    for (const m of content.matchAll(PATTERNS.listDocuments)) out.collections.add(`${m[1]}/${m[2]}`);
    for (const m of content.matchAll(PATTERNS.getDocument)) out.collections.add(`${m[1]}/${m[2]}`);
    for (const m of content.matchAll(PATTERNS.listFiles)) out.buckets.add(m[1]);
  }

  return { ...out, collections: [...out.collections], buckets: [...out.buckets] };
}

async function probeCollection(endpoint, projectId, dbId, collId) {
  try {
    // Appwrite SDK uses JSON-stringified queries; simplest path is no query — endpoint defaults to first 25 docs which is enough to confirm leak.
    const url = `${endpoint}/databases/${encodeURIComponent(dbId)}/collections/${encodeURIComponent(collId)}/documents`;
    const r = await fetch(url, {
      method: "GET",
      headers: {
        "X-Appwrite-Project": projectId,
        "X-Appwrite-Response-Format": "1.6.0",
        "User-Agent": "appwrite-security/0.2 (discover)",
      },
    });
    const body = await r.text();
    let total = 0;
    let returnedRows = 0;
    if (r.status === 200) {
      try {
        const j = JSON.parse(body);
        total = j.total || 0;
        returnedRows = (j.documents || []).length;
      } catch {}
    }
    return {
      status: r.status,
      perms_open: r.status === 200 && returnedRows > 0,
      total_docs: total,
      body_preview: body.slice(0, 200),
    };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

async function probeBucket(endpoint, projectId, bucketId) {
  try {
    const url = `${endpoint}/storage/buckets/${encodeURIComponent(bucketId)}/files`;
    const r = await fetch(url, {
      method: "GET",
      headers: {
        "X-Appwrite-Project": projectId,
        "X-Appwrite-Response-Format": "1.6.0",
        "User-Agent": "appwrite-security/0.2 (discover)",
      },
    });
    const body = await r.text();
    let total = 0;
    let returnedFiles = 0;
    if (r.status === 200) {
      try {
        const j = JSON.parse(body);
        total = j.total || 0;
        returnedFiles = (j.files || []).length;
      } catch {}
    }
    return {
      status: r.status,
      perms_open: r.status === 200 && returnedFiles > 0,
      total_files: total,
      body_preview: body.slice(0, 200),
    };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

export async function discover({ root = process.cwd(), endpoint = null, projectId = null } = {}) {
  const scan = staticScan(root);
  const ep = endpoint || scan.endpoint || "https://cloud.appwrite.io/v1";
  const pid = projectId || scan.projectId;
  const findings = [];
  const probes = { collections: [], buckets: [] };

  if (!pid) {
    return {
      mode: "discover",
      error: "No Appwrite project ID detected in repo. Pass --project or set APPWRITE_PROJECT_ID in .env",
      files_scanned: { source: scan.sourceFiles, env: scan.envFiles },
      collections_found: scan.collections,
      buckets_found: scan.buckets,
    };
  }

  for (const colKey of scan.collections) {
    const [dbId, collId] = colKey.split("/");
    const p = await probeCollection(ep, pid, dbId, collId);
    probes.collections.push({ database: dbId, collection: collId, ...p });
    if (p.perms_open) {
      findings.push({
        check: "collection_perms_open",
        severity: "critical",
        title: `Collection \`${dbId}/${collId}\` is listable anonymously`,
        explain: `GET /databases/${dbId}/collections/${collId}/documents returned ${p.total_docs} documents without auth. The collection's "Read" permission grants \`any\` role.`,
        target: `${dbId}/${collId}`,
        details: { http_status: p.status, total_docs: p.total_docs, body_preview: p.body_preview },
        fix: `// In Appwrite Console:
// Databases -> ${dbId} -> Collections -> ${collId} -> Settings -> Permissions
// REMOVE the "any" role from Read permission. Replace with:
//   - "users"  (only signed-up users)
//   - "team:<id>" (only team members)
//   - Enable "Document Security" and set per-doc perms.`,
        probe: { confirmed: true },
      });
    } else if (p.status === 200 && p.total_docs === 0) {
      findings.push({
        check: "collection_reachable_no_data",
        severity: "info",
        title: `Collection \`${dbId}/${collId}\` reachable anon but empty`,
        explain: "GET succeeded with 200 but 0 docs. Can't distinguish locked from empty. Re-run after seeding.",
        target: `${dbId}/${collId}`,
      });
    }
  }

  for (const bucketId of scan.buckets) {
    const p = await probeBucket(ep, pid, bucketId);
    probes.buckets.push({ bucket: bucketId, ...p });
    if (p.perms_open) {
      findings.push({
        check: "bucket_perms_open",
        severity: "high",
        title: `Storage bucket \`${bucketId}\` is listable anonymously`,
        explain: `GET /storage/buckets/${bucketId}/files returned ${p.total_files} files without auth. Bucket "Read" permission grants \`any\`.`,
        target: bucketId,
        details: { http_status: p.status, total_files: p.total_files, body_preview: p.body_preview },
        fix: `// In Appwrite Console:
// Storage -> Buckets -> ${bucketId} -> Settings -> Permissions
// REMOVE "any" from Read. Set to "users", a team, or enable File-Level Security.`,
        probe: { confirmed: true },
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    mode: "discover",
    scanned_at: new Date().toISOString(),
    scanned_by: "appwrite-security v0.2 (discover)",
    root_dir: root,
    appwrite_endpoint: ep,
    project_id: pid,
    files_scanned: { source: scan.sourceFiles, env: scan.envFiles },
    collections_found: scan.collections,
    buckets_found: scan.buckets,
    probes,
    summary,
    findings,
  };
}
