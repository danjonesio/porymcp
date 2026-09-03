# Writing

## What this guide is for

Text in this repository is read by people: the README on GitHub, the docs, the OpenAPI descriptions in Swagger UI, the dashboard, the changelog and the code comments. The register is plain description: say what the product does, in the words a careful engineer would use to a colleague. A test (`TestProseStyle` in `cmd/server/prose_test.go`) enforces the mechanical rules below. The rest are checked at review.

## Rules the test enforces

`TestProseStyle` runs under `make test` and `go test ./...`. It scans every tracked `.md`, `.yaml`, `.yml`, `.go`, `.ts`, `.tsx`, `.css` and `.mjs` file, plus `NOTICE`, `Dockerfile`, `Makefile` and `.env.example`, and fails naming `file:line:col` for each of the following.

1. **An em-dash (U+2014) or an en-dash (U+2013).** Use a comma, a full stop, a colon or brackets. In a range write "lines 30 to 109", or "30-109" with a hyphen.

| Before | After |
|---|---|
| Real upstream URLs and API keys stay hidden [em-dash] agents only see the proxy. | Real upstream URLs and API keys stay hidden. Agents only see the proxy. |

2. **An arrow (U+2192) in prose.** Write "then", or put a diagram in a fenced block, where arrows are allowed. Inside a fence, arrows and banned words are not checked; dashes and emoji still are.

| Before | After |
|---|---|
| Register upstream [arrow] create key [arrow] point the agent at it. | Register an upstream, create a key, then point the agent at the key's endpoint. |

3. **An emoji or dingbat** (U+1F000 to U+1FAFF, U+2600 to U+27BF, U+2B00 to U+2BFF, U+FE0F). Write the word.

4. **A word from the banned list** (`bannedWords` in `cmd/server/prose_test.go`), matched case-insensitively on word boundaries. The list is the source of truth and this page does not repeat it. It holds marketing adjectives (seamless, robust, powerful, polished, first-class, beautiful, elegant), intensifiers (dead-simple, super simple, trivial, zero-config, out of the box), verbs borrowed from sales copy (unlock, empower, streamline, leverage, delve) and filler (simply, basically, essentially, note that, of course, obviously, let's). In Go files the word check covers comments only, because identifiers such as `Unlock` are not prose. In every other file it covers the whole file, except inside a Markdown fence.

| Before | After |
|---|---|
| Revoked; endpoints are unchanged, they simply stop authenticating. | Revoked. The key stops authenticating. The URLs stay the same. |

Two files are exempt from the word check because they name the words: this page and the test itself.

## Rules the test cannot enforce

Reviewers check these.

1. **No question headings.** A heading states what the section holds. `## Why PoryMCP?` becomes `## What it does`.
2. **No bold-label feature bullets.** A list item that opens with a bold label and a separator is a slide, not a sentence. Write the sentence.

| Before | After |
|---|---|
| `- **API-first** [em-dash] Everything is controllable via API` | Every action in the dashboard is available through the REST API under `/api/v1`. |

3. **No three-adjective lists.** "digital, polymorphic, and able to take many forms" gives the reader nothing to check. Delete it, or keep the one fact that matters.
4. **No contrast for emphasis.** "X, not Y" and "not just X but Y" are rhetoric when Y is a straw man: "Designed as a product, not just infrastructure." Say the true thing once. Keep the contrast when Y is a real alternative outcome: "`unhealthy` outranks `degraded`" and "the filter is corrected by its author and the key is not taken offline" state behaviour, and stay.
5. **No claims dressed as adjectives.** "clean", "modern", "just" and "actually" are not on the banned list because they have technical uses (`path.Clean`, "a clean start"). As a claim about the product they go: "Beautiful modern dashboard" becomes "Dashboard".
6. **No first-person plural.** The repository has no "we". Name the component that does the thing.
7. **No exclamation marks.**
8. **Sentence-case headings.** `## Project Structure (Go example)` becomes `## Project structure (Go example)`.
9. **British spelling**, as the repository already uses: behaviour, catalogue, licence, summarise. Product names and identifiers keep their own spelling: the "Skills catalog" feature, `license` in MIT references, `color` in CSS.
10. **Say what the product does, not how it feels.** Numbers, paths and names instead of adjectives: "one Docker container, a REST API under `/api/v1`, a dashboard at `/`" instead of "Super simple".

## UI copy

Label the thing, state the consequence, stop. A dialog explainer says which field to fill, what the value looks like and what happens when it is wrong. It does not reassure.

| Before | After |
|---|---|
| Usually the address ends in /mcp [em-dash] copy it from the server's documentation or from a working Claude Code or Cursor config. | Usually the address ends in /mcp. Copy it from the server's documentation or from a working Claude Code or Cursor config. |

Placeholders come from `web/src/lib/placeholder.ts`:

- `LOADING` (a non-breaking space, U+00A0) for a value that has not arrived yet. It keeps a tile's height without showing a mark.
- `ABSENT` (`None`) for a value the row will never have: a group key with no enabled upstreams, a log line for a call that named no tool.
- A specific phrase, as a literal at the call site, when the absence has a cause the user should know. The discovery summary shows `Not reported` for a server that answered without a name.

## Comments

A doc comment's first sentence starts with the identifier's name, as `go vet` expects. Say what the code does and, where the shape is a defence, why it is safe: which header is written first and why, which part of a redirect is recorded and why not the rest. No asides and no dashes.

| Before | After |
|---|---|
| `// headersFor is the one place that decides what a credential writes. It builds an http.Header [em-dash] whose Set canonicalises names [em-dash] in the same order ...` | `// headersFor is the one place that decides what a credential writes. It builds an http.Header (whose Set canonicalises names) in the same order ...` |

## Quoting other software

When a line must quote another program's output verbatim and that output carries an emoji or a banned word, add an entry to `quotations` in `cmd/server/prose_test.go` with the file, a substring of the line and the reason. The entry exempts that line from the emoji and word checks only. Dashes and arrows are never exempt: reword around the quotation.

## Decisions recorded

Recorded here so the next rewrite does not reopen them (PORM-130, 2026-09-02).

- The tagline `One key. Many shapes.` stays in the README title block and in the dashboard's meta description. The Porygon sentence that followed it is gone.
- `LOADING` is U+00A0, `ABSENT` is `None`, and the discovery summary's server cell says `Not reported`.
- Go and TypeScript comments follow this guide and were rewritten in the same change as the docs, one commit per package.
- The gate lives at `cmd/server/prose_test.go`, beside the repository's other tracked-file guard, so `make test` runs it without a Makefile change.
