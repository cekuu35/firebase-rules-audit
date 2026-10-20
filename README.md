# firebase-rules-audit

[![CI](https://github.com/cekuu35/firebase-rules-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/cekuu35/firebase-rules-audit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/firebase-rules-audit.svg)](https://www.npmjs.com/package/firebase-rules-audit)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static audit of Firebase **Firestore** and **Storage** security rules for
open access, missing auth checks and anonymous grants — before you deploy
them to production.

Security rules are the entire authorization model for a Firebase app, and
the classic failure is invisible: the SQL-style `allow read, write: if true`
copied from a tutorial during development, then deployed. There is no
linter in the Firebase console that flags it.

Zero dependencies. Reads nothing from the network. Never sends your rules
anywhere. **Free, forever.**

## Quick start

```bash
npx firebase-rules-audit                     # scans ./firestore.rules, ./storage.rules, ./rules/*
npx firebase-rules-audit path/to/firestore.rules --json
```

Exit codes are CI-friendly: `0` clean, `1` any critical/high finding, `2` no
.rules files found.

## What it detects

| Rule | Severity | What it catches |
|---|---|---|
| `OPEN_ACCESS` | critical | `allow read/write: if true;` — anyone, no conditions |
| `ANON_GRANTED` | high | `if request.auth == null` — explicitly grants unauthenticated requests |
| `NO_AUTH_CHECK` | high | condition with no `request.auth` reference at all — unauthenticated clients pass it |
| `LEGACY_RULES_VERSION` / `RULES_VERSION_MISSING` | low | missing or pre-v2 `rules_version` declaration |

Match blocks are parsed with real brace matching, so nested paths
(`/databases/{db}/documents > /users/{uid}`) are attributed correctly and
each `allow` is reported exactly once, at the block that owns it.

## Example output

Scanning the [broken example](examples/broken/firestore.rules):

```
== examples/broken/firestore.rules (firestore+storage, 5 match blocks)
   [CRITICAL] OPEN_ACCESS
       allow read, write: if true — anyone, no conditions, on ... > /users/{userId}
       evidence: allow read, write: if true;
   [HIGH] ANON_GRANTED
       condition explicitly grants unauthenticated requests on ... > /orders/{orderId}
       evidence: request.auth == null
   ...

Summary: 2 critical, 2 high, 0 medium, 1 low
```

## Tests

```bash
npm test
```

6 tests, zero dependencies (Node's built-in test runner): every rule fires on
the broken fixture, the clean fixture stays clean, bind-variable paths parse
fully, nested blocks are never double-reported.

## Honest scope

This is a static linter, not a penetration test or a security guarantee. It
reads your `.rules` files; it does not query your database, verify indexes,
or evaluate rule logic at runtime. A condition can reference `request.auth`
and still be wrong (e.g. checking `!= null` without scoping to the
document's owner) — the tool tells you where to look, not that you are safe.
Pair it with the Firebase emulator's rules unit tests for full coverage.

## The audit family

Free, zero-dependency security auditors in the same shape:

- [mcp-config-security](https://github.com/cekuu35/mcp-config-security) — scan MCP client configs (Claude, Cursor, Windsurf) for leaked tokens
- [supabase-rls-leak-demo](https://github.com/cekuu35/supabase-rls-leak-demo) — red/green fixture proving a Supabase RLS leak, and its one-file fix
- [n8n-workflow-audit](https://github.com/cekuu35/n8n-workflow-audit) — scan exported n8n workflow JSON for hardcoded credentials

## Support

If this tool caught a hole before production did, you can
[buy me a coffee](https://www.buymeacoffee.com/cenkkurtoglu) — completely
optional. The tool is free, no features are locked, and no email is asked.

## License

MIT
