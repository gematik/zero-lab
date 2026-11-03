# pep — backlog

The bff is gone (backlog doc-4); pep is the gateway.

## 1. Cross-AS token acquisition  ·  not a blocker
pep already has per-issuer token sets + per-session DPoP. Add lazy multi-AS acquisition so one login mediates
DPoP-bound tokens for several resource servers.

## 2. Login / chooser UX  ·  ongoing
Error/retry pages, chooser refinements, `userinfo`/session views, accessibility (focus / reduced-motion), and
the close-tab / desktop-redirect edge cases on the decoupled + idpd pages.
