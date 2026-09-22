# Changelog

## [Unreleased]

- `TrustConfig`: environment as data, with `preset_prod`, `preset` (behind
  `dangerous-nonprod`), `for_anchor`, `for_lab_ca` (behind `test-util`) and `validate`.
- Embedded GEM.RCA8 anchor and production roots.json; TEST-ONLY anchors and non-prod
  roots.json behind `dangerous-nonprod`.
- `Env` and `Tier` now come from `ti-types` and are re-exported.
- Crate skeleton.
