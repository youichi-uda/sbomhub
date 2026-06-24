# Distribution rename plan

> Status: M0 planning doc. **No rename is executed by this document.**
> Implementation lands in M2+ as separate issues (see §7).

## 1. Background

SBOMHub is going through the M0 Trust Rescue milestone (Phase 7 strategy pivot).
While taking inventory of distribution channels for issue #14 (9.4.2), we found
several inconsistencies between the GitHub org, the Docker registry, the
Go module paths, and the Homebrew / Scoop manifests that ship today.

This document does three things:

1. Lists the current distribution names (inventory).
2. Lays out the impact matrix for renaming each one.
3. Defines the compatibility strategy and a phased rollout that does not
   break existing users.

The actual rename work is deferred to M2 or later. M0 only commits to
documenting the plan and surfacing user-judgement items in the decision
log (§8).

Related issues:

- #13 (9.4.1) — binary / distribution name unification to `sbomhub`
- #14 (9.4.2) — this doc
- #15 (9.4.3) — `install.sh` smoke test (shipped)
- #16 (9.4.4) — official GitHub Action wrapping the scanner

## 2. Current distribution names (inventory)

Source-of-truth files are listed in the *Source* column so we can re-verify
before any rename.

| Channel                      | Current value                                                | Source                                                                            | Notes                                                                 |
|------------------------------|--------------------------------------------------------------|-----------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| GitHub user/org              | `youichi-uda`                                                | github.com/youichi-uda                                                            | Personal account. Owns both repos today.                              |
| sbomhub repo                 | `github.com/youichi-uda/sbomhub`                             | git remote                                                                        | AGPL-3.0 OSS repo.                                                    |
| sbomhub-cli repo             | `github.com/youichi-uda/sbomhub-cli`                         | git remote                                                                        | MIT-licensed CLI.                                                     |
| Go module (api)              | `github.com/sbomhub/sbomhub`                                 | `apps/api/go.mod`                                                                 | **Note:** module path already uses the `sbomhub/sbomhub` form, *not* `youichi-uda/sbomhub`. Likely set ahead of a future org move; today `go install` against this path does not resolve. |
| Go module (cli)              | `github.com/youichi-uda/sbomhub-cli`                         | sbomhub-cli/`go.mod`, `Makefile`, `.goreleaser.yaml`                              | Matches the repo URL; `go install ...@latest` works today.            |
| CLI binary name              | `sbomhub`                                                    | sbomhub-cli/`Makefile`, `.goreleaser.yaml` builds[].binary                        | Already unified per #13.                                              |
| Docker image (api)           | `y1uda/sbomhub-api` (Docker Hub `docker.io/y1uda/...`)       | `.github/workflows/docker-publish.yml`, `docker-compose.yml`, README badges       | Single registry, single namespace.                                    |
| Docker image (web)           | `y1uda/sbomhub-web` (Docker Hub)                             | same as above                                                                     | Same namespace as api.                                                |
| Homebrew tap (advertised)    | `sbomhub/tap/sbomhub`                                        | sbomhub-cli/README{,_en}.md L17-20                                                | **Drift:** README advertises `sbomhub/tap/...` but `.goreleaser.yaml` publishes to `youichi-uda/homebrew-sbomhub`. The advertised tap does not exist yet. |
| Homebrew tap (configured)    | `youichi-uda/homebrew-sbomhub` (branch `master`)             | sbomhub-cli/`.goreleaser.yaml` brews[].repository                                 | Where releases actually push.                                         |
| Scoop bucket (advertised)    | `https://github.com/sbomhub/scoop-bucket`                    | sbomhub-cli/README{,_en}.md L38                                                   | **Drift:** README points at `sbomhub/scoop-bucket`, goreleaser pushes to `youichi-uda/scoop-sbomhub`. |
| Scoop bucket (configured)    | `youichi-uda/scoop-sbomhub`                                  | sbomhub-cli/`.goreleaser.yaml` scoops[].repository                                | Where releases actually push.                                         |
| CLI install.sh fetch repo    | `youichi-uda/sbomhub-cli`                                    | sbomhub-cli/`scripts/install.sh`                                                  | GitHub Releases URL source.                                           |
| Self-host `install.sh` (api/web) | pulls `y1uda/sbomhub-{api,web}` via `docker-compose.yml` | sbomhub/`install.sh`, `docker-compose.yml`                                        | No registry env override.                                             |
| GitHub Marketplace (Action)  | not published                                                | —                                                                                 | #16 candidate (M1+). No `action.yml` exists today.                    |
| AWS Marketplace              | not listed                                                   | —                                                                                 | Seller account `abyo software 合同会社` is reserved for S4 products. SBOMHub listing is out of scope for now. |
| Cloudflare Marketplace       | n/a                                                          | —                                                                                 | Not a target channel.                                                 |

## 3. Rename impact matrix

`Impact` measures user-facing breakage (LOW = transparent / link redirect handles
it; MEDIUM = users must change a pulled URL but stay on the same tooling;
HIGH = fork URLs, CI configs, and import paths break unless mirrored).

| From                                     | To (proposed, *placeholder*)            | Impact | Breaking? | Compatibility strategy                                                                 |
|------------------------------------------|-----------------------------------------|--------|-----------|----------------------------------------------------------------------------------------|
| GitHub user `youichi-uda`                | new org (see Decision log §8)            | HIGH   | semi      | GitHub native rename auto-redirects URLs / clones / API for both repos.                |
| `youichi-uda/sbomhub` repo               | `<new-org>/sbomhub`                     | HIGH   | semi      | Covered by org rename redirect. README badges and `docs/` links must still be updated. |
| `youichi-uda/sbomhub-cli` repo           | `<new-org>/sbomhub-cli`                 | HIGH   | semi      | Same. Plus `scripts/install.sh` `REPO=` constant.                                      |
| Go module `github.com/sbomhub/sbomhub`   | keep as-is, or align to `<new-org>`     | LOW    | maybe     | Currently does not resolve via `go install` (no module proxy match). M2 decision.      |
| Go module `github.com/youichi-uda/sbomhub-cli` | `github.com/<new-org>/sbomhub-cli` | MEDIUM | YES       | `go install` import path changes. Bump to v2 if we want to keep the v1 path alive.     |
| Docker images `y1uda/sbomhub-{api,web}`  | `<new-namespace>/sbomhub-{api,web}` on GHCR and/or Docker Hub | MEDIUM | YES | Dual-push for ≥6 months. `docker-compose.yml` and `install.sh` updated. Old tags stay readable indefinitely. |
| Homebrew tap drift (`sbomhub/tap` vs `youichi-uda/homebrew-sbomhub`) | one canonical tap, see Decision log | MEDIUM | YES (today's README is wrong) | Fix advertised tap to match the published one *now* as a small follow-up, then rename to the final canonical tap during the org move. |
| Scoop bucket drift (`sbomhub/scoop-bucket` vs `youichi-uda/scoop-sbomhub`) | one canonical bucket | MEDIUM | YES (today's README is wrong) | Same as Homebrew.                                                                      |
| GitHub Marketplace Action (new)          | `<new-org>/sbomhub-action`              | n/a    | n/a       | Greenfield; only matters once #16 ships.                                               |

> The "drift" rows for Homebrew and Scoop are pre-existing inconsistencies,
> not rename impact. They should be resolved before any rename so we are
> moving from a single known state.

## 4. Compatibility strategy

### 4.1 GitHub org rename

- GitHub redirects all old org URLs (repo HTTPS, SSH, API, raw, release assets,
  issue links) to the new org permanently, as long as no new org or user
  claims the old name.
- Clone URLs (`git clone` and `git remote get-url`) continue to work; they
  redirect at fetch time and the user is prompted to update.
- Caveat: third-party services that hard-code the old org in URLs (Docker
  Hub badges, external CI configs, documentation in other projects) do not
  auto-update. We must crawl our own README badges and `docs/` after the
  rename.
- Caveat: container registries are a *different* namespace (`docker.io` and
  `ghcr.io`). The GitHub org rename has no effect on image URLs.

### 4.2 Docker image rename

- Keep `docker.io/y1uda/sbomhub-{api,web}` pushable for at least 6 months
  after the new registry path goes live. `.github/workflows/docker-publish.yml`
  pushes the same tags to both old and new namespaces during the overlap.
- Add a `SBOMHUB_IMAGE_REGISTRY` environment variable to `docker-compose.yml`
  so operators can flip between namespaces without editing the file
  (default: new registry once rollout starts).
- Document the change in `docs/UPGRADE.md` with concrete `docker pull`
  commands. Add a `deprecated` note on the old Docker Hub repo description.

### 4.3 Homebrew / Scoop rename

- Drift fix (precondition): pick one canonical tap and one canonical bucket
  *now* and align both `.goreleaser.yaml` and the README before the rename
  starts. Either:
  - keep `youichi-uda/homebrew-sbomhub` + `youichi-uda/scoop-sbomhub` and
    fix the README; or
  - move both to a `sbomhub/...` repo (requires owning the org name).
- During rename: publish to both old and new tap / bucket for at least one
  release cycle.
- Old tap formula emits a `caveats` block telling users to switch.
- After the deprecation window: stop publishing new versions to the old tap,
  keep old formulas installable for users on pinned versions.

### 4.4 Go module rename (sbomhub-cli)

- Import path break is real. Options:
  1. **Hold:** keep `github.com/youichi-uda/sbomhub-cli` even after the
     GitHub org rename. GitHub redirect makes `go install` against the old
     path keep working *as long as no new user claims `youichi-uda`*.
  2. **v2 bump:** rename to `github.com/<new-org>/sbomhub-cli/v2`, leaving
     v1 on the old path indefinitely. Aligns with semver expectations.
- Recommendation: option 1 for the first 6 months (the CLI is a binary, not
  a library — almost nobody imports it programmatically), then v2 bump
  bundled with M3 or M4.
- For sbomhub-api: its module path is already `github.com/sbomhub/sbomhub`,
  which does *not* match the repo URL. It is not consumed via `go install`
  (the api ships as a Docker image / source build), so this drift is
  effectively harmless today. M2 decision: align to the canonical path or
  leave it.

### 4.5 install.sh

- `sbomhub/install.sh` calls `docker compose pull` against whatever is in
  `docker-compose.yml`. Once §4.2 lands, this automatically picks up the
  new registry.
- `sbomhub-cli/scripts/install.sh` has `REPO="youichi-uda/sbomhub-cli"`
  hard-coded. Must be updated in lockstep with the GitHub org rename. Old
  install.sh users get a clean curl `404` if the redirect chain breaks
  (GitHub redirects HTML, not always API), so we should publish a wrapper
  script under the old path that points at the new location.

## 5. Phased rollout (M2+)

### Phase 0 (precondition, can ship in M0/M1)

- Fix the Homebrew / Scoop README ↔ goreleaser drift (§4.3 drift fix). This
  is a docs / config change, not a rename.
- Add `SBOMHUB_IMAGE_REGISTRY` plumbing to `docker-compose.yml`
  (defaults to `y1uda` so behaviour does not change).

### Phase 1 (M2 + ~1 month)

- Create the new GitHub org (name TBD — see §8).
- Stand up the new Docker registry namespace (GHCR and/or Docker Hub).
- `docker-publish.yml` dual-pushes to old and new namespaces.
- New Homebrew tap / Scoop bucket repos created; goreleaser dual-publishes.

### Phase 2 (M2 + ~3 months)

- `git mv` both repos into the new org (GitHub transfer). Redirects live.
- `docker-compose.yml` default registry flipped to the new namespace.
- README badges, `docs/` URLs, `install.sh` `REPO=`, MCP server `homepage`
  fields all updated.
- `sbomhub-cli` Homebrew formula renamed to point at the new tap
  (`<canonical-tap>/sbomhub`).

### Phase 3 (M2 + ~6 months)

- Old Docker Hub repos marked deprecated in their description, new pushes
  stop. Existing tags remain pullable.
- Old Homebrew tap / Scoop bucket marked deprecated; final release
  published with a caveats block.
- Go module v2 bump for `sbomhub-cli` if we go that route (§4.4).

## 6. Out of scope (not decided here)

- Commercial / hosted branding (SBOMHub Cloud, SBOMHub Enterprise).
- AWS Marketplace listing under `abyo software 合同会社`. CLAUDE.md reserves
  that seller account for S4 products; SBOMHub Marketplace listing has not
  been decided.
- Cloudflare Marketplace, JetBrains plugin, VSCode extension, or any other
  channel not listed in §2.
- Renaming the project (the *product name* SBOMHub stays; this doc is only
  about distribution surface names).
- Logo / icon updates (handled per `../abyo-software` and `../s4*` assets
  conventions when commercial branding is decided).

## 7. Related issues

- **#13** (9.4.1) — binary / distribution name unification. CLI binary
  already named `sbomhub`. Aligns with this doc.
- **#14** (9.4.2) — this doc.
- **#15** (9.4.3) — `install.sh` smoke test in CI. Shipped.
- **#16** (9.4.4) — official GitHub Action wrapping `sbomhub scan`.
  Will create a new Marketplace surface area; see §3 last row.
- (future) M2+ issue to execute Phase 0/1/2/3 above. To be filed when
  decision log §8 items are resolved.

## 8. Decision log (user judgement required)

The following are blockers for Phase 1 onward. Phase 0 (drift fix) does
not depend on any of them.

- [ ] **New GitHub org name.** Candidates:
  - `sbomhub-io` — most idiomatic, communicates project identity.
  - `sbomhub` — requires the personal account to give up the matching
    namespace; cleanest URL.
  - `abyo-software` — aligns with the AWS Marketplace seller (`abyo
    software 合同会社`) and existing `../abyo-software` repo conventions.
    Couples SBOMHub branding to the commercial entity.
  - Keep `youichi-uda` — do nothing. Acceptable if commercial branding is
    out of scope.
- [ ] **Docker registry strategy.**
  - `ghcr.io/<new-org>/...` — free for OSS, tighter GitHub integration,
    matches the GitHub org rename.
  - `docker.io/<new-namespace>/...` — preserves badge URLs format and is
    what users already pull.
  - Both — most user-friendly, doubles publish time and CI minutes.
- [ ] **Homebrew tap owner.** Personal (`youichi-uda/homebrew-sbomhub`,
  status quo modulo README fix) vs org (`<new-org>/homebrew-tap`).
- [ ] **Scoop bucket owner.** Same question for Scoop.
- [ ] **Go module path for `sbomhub-api`.** Keep the
  `github.com/sbomhub/sbomhub` path that nobody imports, or align it to the
  repo URL? Decide at M2.
- [ ] **`sbomhub-cli` v2 bump timing.** Bundle the import-path change with
  M3 / M4, or defer indefinitely.

## 9. To verify before executing any phase (※要確認)

Items the inventory left as "needs verification" rather than baking in
assumptions:

- ※ Whether `github.com/sbomhub` (the GitHub user/org used in the
  `apps/api/go.mod` module path) is currently owned by anyone. If not, it
  is squatable. If owned by an unrelated party, the api module path is
  effectively broken and must be aligned.
- ※ Whether `sbomhub` Docker Hub namespace is available (vs already
  squatted). Determines whether `docker.io/sbomhub/sbomhub-{api,web}` is a
  viable target.
- ※ Whether `sbomhub-io` / `sbomhub` GitHub org names are available.
- ※ The actual `homebrew-sbomhub` and `scoop-sbomhub` repos under
  `youichi-uda` — are they currently published and consumed by users? If
  yes, the §4.3 drift fix must dual-publish during the README correction
  rather than re-pointing cold.
- ※ Number of external CI configs / Dockerfiles in the wild pinning
  `y1uda/sbomhub-api`. Sets the floor for the §4.2 dual-push window.
