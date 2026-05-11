#!/usr/bin/env node
// Appwrite Security Auditor — pure Node.js, no deps.
//
// Usage:
//   APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1 APPWRITE_PROJECT_ID=xxx APPWRITE_API_KEY=xxx node audit.js
//   node audit.js --endpoint URL --project ID --key K [--no-probe] [--html report.html]
//
// API key needs scopes: collections.read, databases.read, projects.read, users.read

import { writeFileSync } from "node:fs";

const UA = "appwrite-security/0.1";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  permission_any_role: {
    severity: "critical",
    title: "Permission grants 'any' role — anyone can perform this operation",
    explain: "The `any` role in Appwrite means literally anyone, no auth required. Combined with read or list, the entire collection is publicly readable.",
  },
  permission_users_too_broad: {
    severity: "high",
    title: "Permission grants 'users' role — every signed-up user can perform this op",
    explain: "The `users` role lets ANY authenticated user (including a freshly self-registered one) perform this operation across the entire collection. Tighten with team or document-level perms.",
  },
  collection_no_document_security: {
    severity: "high",
    title: "Document security is OFF on a permission-protected collection",
    explain: "When document security is disabled, ALL documents in the collection share the collection-level permissions. A single overly broad rule exposes everything. Enable document security to set per-row perms.",
  },
  team_role_with_wildcard: {
    severity: "medium",
    title: "Team-based permission lacks role specificity",
    explain: "team:<id> without a specific role grants the operation to every member of the team regardless of role.",
  },
  oauth_provider_misconfigured: {
    severity: "medium",
    title: "OAuth2 provider enabled without restricting redirect URLs",
    explain: "Open redirect attack vector — restrict to known domains via the project settings.",
  },
  email_auth_no_verification: {
    severity: "medium",
    title: "Email/Password auth enabled without verification requirement",
    explain: "Anyone can self-register with fake emails to bypass email-gated workflows.",
  },
};

async function api(endpoint, project, key, path) {
  const r = await fetch(`${endpoint}${path}`, {
    headers: {
      "X-Appwrite-Project": project,
      "X-Appwrite-Key": key,
      "User-Agent": UA,
    },
  });
  if (!r.ok) throw new Error(`API ${path} failed: ${r.status} ${await r.text().then(t => t.slice(0, 200))}`);
  return r.json();
}

async function probeAnonAccess(endpoint, project, dbId, collectionId) {
  try {
    const r = await fetch(`${endpoint}/databases/${dbId}/collections/${collectionId}/documents?queries[]=limit(1)`, {
      headers: {
        "X-Appwrite-Project": project,
        "User-Agent": UA,
      },
    });
    const status = r.status;
    if (!r.ok) {
      return { confirmed: false, status, reason: status === 401 || status === 403 ? "auth required" : `http ${status}` };
    }
    const body = await r.text();
    let row_count = 0;
    let columns = [];
    try {
      const parsed = JSON.parse(body);
      const items = parsed.documents || [];
      row_count = parsed.total ?? items.length;
      if (items[0] && typeof items[0] === "object") columns = Object.keys(items[0]).filter((k) => !k.startsWith("$"));
    } catch { /* non-JSON */ }
    return {
      confirmed: true,
      status,
      sample: { row_count, columns: columns.slice(0, 8), bytes_returned: body.length },
    };
  } catch (e) {
    return { confirmed: false, status: 0, reason: `network error: ${e.message}` };
  }
}

// Permission strings look like:  "read(\"any\")",  "create(\"users\")",  "update(\"team:abc\")"
function parsePermission(p) {
  const m = String(p).match(/^([a-z]+)\("([^"]+)"\)$/);
  if (!m) return null;
  return { action: m[1], role: m[2] };
}

function classifyPermissions(perms) {
  const findings = [];
  for (const p of perms) {
    const parsed = parsePermission(p);
    if (!parsed) continue;
    if (parsed.role === "any") {
      findings.push({ check: "permission_any_role", action: parsed.action, role: parsed.role, raw: p });
    } else if (parsed.role === "users") {
      findings.push({ check: "permission_users_too_broad", action: parsed.action, role: parsed.role, raw: p });
    } else if (/^team:[a-z0-9]+$/i.test(parsed.role)) {
      findings.push({ check: "team_role_with_wildcard", action: parsed.action, role: parsed.role, raw: p });
    }
  }
  return findings;
}

export async function audit(opts) {
  const { endpoint, project, key, activeProbe = true } = opts;
  if (!endpoint || !project || !key) throw new Error("audit() requires { endpoint, project, key }");

  const findings = [];
  const databases = await api(endpoint, project, key, "/databases?queries[]=limit(100)");
  const dbs = databases.databases || [];

  let probed = 0;
  let confirmed = 0;
  let totalCollections = 0;

  for (const db of dbs) {
    const colsResp = await api(endpoint, project, key, `/databases/${db.$id}/collections?queries[]=limit(100)`);
    const cols = colsResp.collections || [];
    totalCollections += cols.length;

    for (const col of cols) {
      const target = `${db.name}.${col.name}`;
      const permFindings = classifyPermissions(col.$permissions || []);

      for (const pf of permFindings) {
        const finding = {
          check: pf.check,
          ...CHECKS[pf.check],
          target: `${target} (${pf.action})`,
          details: {
            database: db.name,
            collection: col.name,
            collection_id: col.$id,
            action: pf.action,
            role: pf.role,
            raw_permission: pf.raw,
            document_security_enabled: col.documentSecurity,
          },
          fix_sql: `// In the Appwrite console: Databases → ${db.name} → ${col.name} → Settings → Permissions
// Remove "${pf.raw}" and replace with a more restrictive role.
// For per-document ownership, enable Document Security and set per-document perms via the SDK.`,
        };

        if (activeProbe && (pf.action === "read" || pf.action === "list") && pf.role === "any") {
          const probe = await probeAnonAccess(endpoint, project, db.$id, col.$id);
          finding.probe = probe;
          probed++;
          if (probe.confirmed) confirmed++;
        }
        findings.push(finding);
      }

      // Document security disabled but has permissions = single point of failure
      if (!col.documentSecurity && permFindings.some((pf) => pf.action === "read" || pf.action === "list")) {
        findings.push({
          check: "collection_no_document_security",
          ...CHECKS.collection_no_document_security,
          target,
          details: { collection_id: col.$id, document_security: false },
          fix_sql: `// In the Appwrite console: Databases → ${db.name} → ${col.name} → Settings → Document Security = ON
// Then iterate existing documents and set per-document perms via the Appwrite SDK or REST.`,
        });
      }
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    appwrite_endpoint: endpoint,
    appwrite_project: project,
    scanned_at: new Date().toISOString(),
    scanned_by: "appwrite-security v0.1",
    active_probe: { enabled: activeProbe, probed, confirmed },
    summary,
    n_databases: dbs.length,
    n_collections: totalCollections,
    findings,
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.error(`Usage:
  Full audit (needs API key):
    appwrite-security [--endpoint URL --project ID --key API_KEY] [--no-probe] [--html report.html]

  Keyless discover (parses local repo + probes only with public API):
    appwrite-security --discover [path]
    appwrite-security --discover . --project xxx --endpoint https://cloud.appwrite.io/v1

Env vars: APPWRITE_ENDPOINT, APPWRITE_PROJECT_ID, APPWRITE_API_KEY
API key needs scopes: collections.read, databases.read, projects.read.
--discover: no API key needed; parses .listDocuments() call sites + probes public REST anon.`);
    process.exit(1);
  }

  // --discover mode (v0.2): no API key needed.
  if (args.includes("--discover")) {
    const { discover } = await import("./discover.js");
    const idx = args.indexOf("--discover");
    const path = args[idx + 1] && !args[idx + 1].startsWith("--") ? args[idx + 1] : process.cwd();
    const endpointOverride = args.includes("--endpoint") ? args[args.indexOf("--endpoint") + 1] : null;
    const projectOverride = args.includes("--project") ? args[args.indexOf("--project") + 1] : null;
    const result = await discover({ root: path, endpoint: endpointOverride, projectId: projectOverride });

    const htmlIdx = args.indexOf("--html");
    if (htmlIdx !== -1) {
      const out = args[htmlIdx + 1] || "discover-report.html";
      const { renderHtml } = await import("./report.js");
      writeFileSync(out, renderHtml(result));
      console.error(`Discover report written to ${out}`);
    }
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const flag = (k) => args.includes(k) ? args[args.indexOf(k) + 1] : null;
  const endpoint = flag("--endpoint") || process.env.APPWRITE_ENDPOINT;
  const project = flag("--project") || process.env.APPWRITE_PROJECT_ID;
  const key = flag("--key") || process.env.APPWRITE_API_KEY;
  const activeProbe = !args.includes("--no-probe");

  if (!endpoint || !project || !key) {
    console.error("Error: provide --endpoint, --project, --key (or APPWRITE_ENDPOINT / APPWRITE_PROJECT_ID / APPWRITE_API_KEY env vars)");
    console.error("\nTip: try --discover for a keyless scan of your local repo:");
    console.error("  appwrite-security --discover .");
    process.exit(1);
  }

  const result = await audit({ endpoint, project, key, activeProbe });

  const htmlIdx = args.indexOf("--html");
  if (htmlIdx !== -1) {
    const out = args[htmlIdx + 1] || "report.html";
    const { renderHtml } = await import("./report.js");
    writeFileSync(out, renderHtml(result));
    console.error(`HTML report written to ${out}`);
    console.error(`Findings: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium${result.active_probe.enabled ? ` (${result.active_probe.confirmed} CONFIRMED via active probe)` : ""}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
