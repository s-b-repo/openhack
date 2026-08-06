# Vendored knowledge indexes

Three JSON manifests that map OpenHack's `Checklist.VulnClass.id` to external catalogues, so `Combinations` can compute payload-family / WSTG / HackTricks coverage without touching the network at test time.

We vendor **taxonomy**, not raw payload strings — the algorithm only needs the *shape* of what families exist per class, not the payloads themselves. The upstream repos stay authoritative.

| Index | Source | License |
|---|---|---|
| `payloadsallthethings-index.json` | [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | MIT |
| `hacktricks-index.json` | [book.hacktricks.wiki](https://book.hacktricks.wiki) | CC-BY-4.0 |
| `wstg-index.json` | [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) | CC-BY-SA-4.0 |

## Refreshing

The indexes are refreshed by an opt-in script:

```
bun run packages/openhack/script/ingest-knowledge.ts
```

It clones PayloadsAllTheThings to a temp dir, walks the directory tree, and rewrites `payloadsallthethings-index.json`. For HackTricks / WSTG it currently updates only the `version` field (the URL / id mappings are curated by hand — they change rarely and blindly scraping them would introduce brittleness).

**Never run at boot.** The knowledge loader (`packages/openhack/src/knowledge.ts`) reads only what's vendored; a fresh checkout with never-refreshed indexes still works.

## Adding a class

1. Add the entry to `Checklist.CLASSES[]` in `packages/openhack/src/checklist.ts` if it's not already there.
2. Add its payload families to `payloadsallthethings-index.json` under `byClass.<classId>` — each family needs `{ id, hint, upstreamPath }`.
3. Add its HackTricks / WSTG entries to the other two indexes.
4. `bun test test/knowledge.test.ts` from `packages/openhack/` — the tests check that every class-id in the indexes exists in `Checklist.all()`, that every family has a non-empty `hint`, and that URLs point at `book.hacktricks.wiki` domains.

## Attribution

- PayloadsAllTheThings by Swissky and contributors — MIT — https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks by Carlos Polop and contributors — CC-BY-4.0 — https://book.hacktricks.wiki
- OWASP Web Security Testing Guide by the OWASP Foundation — CC-BY-SA-4.0 — https://owasp.org/www-project-web-security-testing-guide/
