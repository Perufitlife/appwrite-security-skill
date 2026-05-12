# Appwrite Security Auditor

> Audit any Appwrite project for over-permissive collection/document permissions. Get a shareable HTML report with a fix snippet on every finding. **Active probe fetches data anonymously to PROVE leaks live — not just infer them.**

> ▶ **Run it without installing anything →** [apify.com/renzomacar/appwrite-security-auditor](https://apify.com/renzomacar/appwrite-security-auditor) (paste endpoint + project ID + API key, get HTML report)

> ⚡ Want me to run it for you and send back a written report? **$99, 24h delivery →** https://perufitlife.github.io/supabase-security-skill/ (one landing covers all five — Supabase, PocketBase, Appwrite, Hasura, Firebase)

> 🔁 **Want this running on a cron?** [RLS Monitor](https://rls-monitor.vercel.app/) does weekly diff-based scans + email alerts when new findings appear — $29/mo, your keys never leave your CI.
>
> 📦 **Need all 5 BaaS stacks at once?** The [BaaS Security Pack](https://perufitlife.github.io/supabase-security-skill/pack.html) bundles every scanner + sample reports + fix-SQL libraries — one $99 download.

> 🪞 **Sister tool**: [aitells](https://aitells.vercel.app/) detects + rewrites AI fingerprints in your text (em-dashes, "delve", parallel bullets). Free detector + $19 lifetime rewriter at [/rewrite](https://aitells.vercel.app/rewrite).

[![npm](https://img.shields.io/npm/v/appwrite-security?color=red)](https://www.npmjs.com/package/appwrite-security) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue)

> **Sister tools** for other BaaS platforms (same `--discover` flag, all MIT):
> [supabase-security](https://www.npmjs.com/package/supabase-security) · [pocketbase-security](https://www.npmjs.com/package/pocketbase-security) · [firebase-security](https://www.npmjs.com/package/firebase-security) · [nhost-security](https://www.npmjs.com/package/nhost-security)

## Why this exists

Appwrite has a powerful but easy-to-misuse permission model: collections can grant operations (`read`, `list`, `create`, `update`, `delete`) to roles like `any`, `users`, `team:<id>`, or `user:<id>`. Three patterns I see over and over:

- **`any` role on read or list** — the collection is fully public. Anyone can dump every document without auth.
- **`users` role too broadly** — any signed-up user (including a self-registered anonymous one) reads or writes the entire collection.
- **Document Security disabled** — collection-level perms apply to ALL documents. A single broad rule exposes everything.

This auditor surfaces all of them across every database/collection in your project in one command.

## Install + run

```bash
APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1 \
APPWRITE_PROJECT_ID=your-project-id \
APPWRITE_API_KEY=your-server-key \
npx appwrite-security --html report.html
```

Or:

```bash
npx appwrite-security \
  --endpoint https://cloud.appwrite.io/v1 \
  --project xxx \
  --key xxx \
  --html report.html
```

## What it checks

| # | Check | Severity |
|---|---|---|
| 1 | Permission grants `any` role (anyone can perform op) | **CRITICAL** |
| 2 | Permission grants `users` role (every signed-up user passes) | HIGH |
| 3 | Document Security OFF on permission-protected collection | HIGH |
| 4 | Team-based permission lacks role specificity | MEDIUM |
| 5 | OAuth2 provider misconfig | MEDIUM |
| 6 | Email auth without verification | MEDIUM |

## Active probe

Default: ON. After detecting a `read("any")` or `list("any")` permission, the auditor sends an **anonymous GET** to `/v1/databases/{db}/collections/{col}/documents?queries[]=limit(1)`. If documents come back, the finding is `confirmed: true` with row count, columns visible, and bytes leaked.

`--no-probe` disables the live fetch (passive metadata-only mode).

## How to get an API key

1. Open your Appwrite console → Project Settings → API Keys → "Create API Key"
2. Required scopes: `databases.read`, `collections.read`, `projects.read`
3. Copy the key immediately (Appwrite shows it only once)

The key is used only for this run's metadata reads. Never persisted.

## License + source

MIT. Open source: https://github.com/Perufitlife/appwrite-security-skill

For Supabase, see https://github.com/Perufitlife/supabase-security-skill
For PocketBase, see https://github.com/Perufitlife/pocketbase-security-skill


## Want it done for you?

Two productized services:

- [**Vibe-code Security Review** — $199 / 48h](https://buy.stripe.com/bJe00jgik4EqdWV2iScAo0n) — I review your AI-generated code (Cursor / Claude / v0 / Bolt) and ship a PDF with fixes ranked by exploitability.
- [**Sandbox-as-a-Service** — $499 / 48h](https://buy.stripe.com/aFa7sLc243Amf0Z5v4cAo0l) — custom partner integration sandbox built for your API.

## Integration pattern reference

See [`rotatepilot-skyx-sandbox`](https://github.com/Perufitlife/rotatepilot-skyx-sandbox) for a live demo of how a partner consumes one of our public REST APIs in a single static page — built 12-may-2026 in response to an aviation-platform partnership inbound. Same JSON-contract / CORS / edge-served approach we use for `appwrite-security` integrations.

## Sister AI text tools

If your team writes outreach, PR descriptions, or social posts with AI, the [aitells](https://aitells.vercel.app) ecosystem catches the fingerprints before they ship:

- [`@perufitlife/aitells-mcp`](https://www.npmjs.com/package/@perufitlife/aitells-mcp) — MCP server for Claude Code / Cursor. `detect_ai_tells` + `humanize_text` as native tools.
- [`Perufitlife/aitells-action`](https://github.com/Perufitlife/aitells-action) — GitHub Action that scans PR titles/bodies/commits for AI patterns. Posts friendly summary comment.
- [aitells.vercel.app](https://aitells.vercel.app) — free detector + $19 lifetime humanizer (first 100 buyers)
