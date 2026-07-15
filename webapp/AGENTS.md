# AGENTS.md

Guidance for coding agents working inside `webapp/`.

## Coding Standards

Follow `webapp/STYLE_GUIDE.md` for canonical style, accessibility, and testing standards.

## Shared Components

Prefer the shared components from `@mattermost/shared` over hand-rolled equivalents:

- **`Button`** — use for text-based button UI instead of building bespoke `<button>` elements or styling.
  ```typescript
  import {Button} from '@mattermost/shared/components/button';
  ```
- **`WithTooltip`** — use for tooltips instead of wiring up Floating UI or other tooltip primitives directly.
  ```typescript
  import {WithTooltip} from '@mattermost/shared/components/tooltip';
  ```

Always import via the full package name (`@mattermost/shared/...`), never via relative paths into `platform/shared/`.

## Plugin-facing global surface

The web app exposes several top-level `window.*` globals to plugins. **Not all of them are stable.** This section covers only the *published* subset — allowlisted entries whose contract types live in `@mattermost/shared/types/global/` and which are asserted against the real implementation at build time. Third-party plugins pin against those via `min_server_version`, so treat every published entry like a public API.

Stable, published surfaces this doc applies to:

- `window.WebappUtils.modals.openModalById` / `canOpenModalId` (contract: `PublishedModalUtils`).
- `window.Editor` (contract: `PublishedEditorUtils`).

Explicitly **not** stable, and outside this doc:

- `window.Components` — internal-plugin-only, documented at `webapp/channels/src/plugins/export.ts` as "may have breaking changes in the future outside of major releases". Do not treat additions here as public API.
- `window.ProductApi` — a prototype for internal plugins during the transition to module federation, per the comment at the same file.

Other legacy fields on `window.WebappUtils` (`browserHistory`, `notificationSounds`, `channels`, `popouts`, etc.) predate the published-allowlist pattern; changes to those still warrant a plugin-compat review, but they are not governed by the drift-check machinery below.

**Where things live**

- Contract types: `webapp/platform/shared/src/types/global/*.ts` (e.g. `PublishedModalUtils`, `PublishedEditorUtils`). Do not import channels internals here — if a needed type lives in `webapp/channels`, move the type portion to `@mattermost/types` or `@mattermost/shared/types/global/` first.
- Concrete implementations and allowlists: `webapp/channels/src/plugins/published_*.ts`.
- Wiring onto `window`: `webapp/channels/src/plugins/export.ts`.

**Contract drift**

Each allowlist file must assert that its real components/functions stay assignable to the published contract at build time (see `ContractHonored` + `AssertPublished*Contract` in `published_modals.ts` and `published_editor.ts`). Do not remove those `type Assert*Contract = ...` aliases — they look unused but are the only thing that makes `tsc` fail on drift.

**Adding an entry**

1. Add the type to `platform/shared/src/types/global/<file>.ts`.
2. Add the implementation to the corresponding `channels/src/plugins/published_<file>.ts` allowlist.
3. Add a unit test to `published_<file>.test.ts`.
4. Only wire it onto `window` in `export.ts` once 1–3 land in the same PR.

**Removing or changing an entry**

Mark it `@deprecated` in the shared type for at least two minor releases before deletion, and call it out in the PR description. Never silently change a field's type — that breaks plugins pinned to an older `min_server_version`.
