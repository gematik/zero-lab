---
id: TASK-46
title: 'Fuzz targets for ti-pkcs12: decode with MAC, KDF and PBE parameters'
status: Done
assignee: []
created_date: 2026-10-14 20:42
updated_date: '2026-10-29T12:02:00Z'
labels:
  - ti-pkcs12
  - fuzz
milestone: m-0
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 44000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. ti-pkcs12 decodes identity files from outside; the iteration limits (P12-036) make fuzzing affordable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-pkcs12/fuzz with a decode target seeded from spec/pkcs12, asserting no panic, bounded time and the spec result codes, and just fuzz-ti-pkcs12
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
rust/ti-pkcs12/fuzz, Ziel decode: Eingabe = Längenbyte, Passwort, Datei. Startdateien erzeugt just fuzz-ti-pkcs12 aus einem frischen spec/pkcs12-Konformitätskorpus plus den Vendor-Dateien (58, Ergebnisse wie im Manifest erwartet; nicht eingecheckt, um keine 540 KB Testschlüssel zu duplizieren). Prüft: kein Panic, nur Ergebniscodes der Spec, P12-036 bei limit_exceeded und MAC, Paar-Indizes gültig. Zeit und Speicher: -timeout=30, -malloc_limit_mb=256. 4,48 Mio. Läufe in 300 s ohne Fund. Beobachtung: P12-036 begrenzt jede Iterationszahl einzeln, nicht die Summe über alle Taschen einer Datei.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fuzz-Ziel decode für ti-pkcs12 mit Rezept just fuzz-ti-pkcs12, Startdateien aus spec/pkcs12; 4,48 Mio. Läufe ohne Fund; development.md ergänzt.
<!-- SECTION:FINAL_SUMMARY:END -->
