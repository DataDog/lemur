@README.md

- Accuracy first. Every edge and factual claim needs repository/configuration evidence
  or an explicit unverified note. This site is seeded from the certificate north-star
  investigation; the current flow steps and several components are marked `unverified`.
  Do not inherit claims without checking them. A refresh pass should tighten the
  `unverified` steps with real source paths and `verification: verified`.
- Change `model.yaml` and `lemur-certificate-architecture.md`, never generated d2/JSON.
  Preserve view IDs and exact component spelling. Architecture membership uses base
  edges; flows use a scenario and 3-8 ordered steps referencing base pairs. Never add
  flow IDs to base-edge membership or number architecture arrows.
- Component sections are `###` H3 headings followed by `<!-- catalog: no-service -->`;
  the generator derives their slug from the heading text (slugified), which must match
  the node's `doc:` in `model.yaml`. View sections are `##` H2 headings with
  `<!-- view: <id> -->`.
- `Source:` paragraphs must be valid citations: backtick code spans separated by
  commas, optionally prefixed `in <alias>, ` for external repositories. Do not wrap the
  whole Source line in one code span.
- A d2 with TALA (v0.9.0+) must be on PATH (`export PATH="$HOME/.local/d2bin:$PATH"`).
  Run `./generate-diagram.py --check` after any model/prose change.
- This repository owns `src/`. The web-ui static-app mirror is generated later with
  `--web-ui /path/to/web-ui`. Keep generated `dist/`/JSON/d2 untracked.
- Keep labels short; exact names keep their spelling. Inspect rendered views after any
  layout change; layout problems do not show up in diffs.
