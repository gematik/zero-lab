---
id: TASK-341
title: >-
  oidf: one configuration type for YAML and JSON, with entity and master as its
  names
status: Done
assignee: []
created_date: '2026-11-16T18:14:00Z'
updated_date: '2026-11-16T18:32:00Z'
labels: []
dependencies: []
ordinal: 356000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
oidf.FileConfig is read from YAML by zero-pdp and zero-pep-proxy; zeta-pdp-go reads a JSON file into a type of its own and copies it over, with other names (entity, master, master_jwk). The maintainer wants one type for both (2026-11-16): FileConfig and what it holds get json tags beside the yaml ones, with the same names, and the names become entity (was sub), master (was fed_master_url), master_entity_statement_uri and master_jwk. A configuration with the old names is refused at start (unknown field), as every misspelt one is; the release notes say so.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 FileConfig reads the same relying party from YAML and from JSON
- [x] #2 The names are entity, master, master_entity_statement_uri and master_jwk in both; the old ones are refused
- [x] #3 zero-pdp, zero-pep-proxy, their examples and tests use the new names
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FileConfig, RelyingPartyConfig, RelyingPartyMetadata, FederationEntity, KeyFiles and KeyFile carry json tags with the names of the yaml ones. Renamed in both: sub to entity, fed_master_url to master, fed_master_entity_statement_uri to master_entity_statement_uri, fed_master_jwk to master_jwk; the messages of Validate name the new ones. oidf/testdata has the relying party as YAML and as JSON, and zero-pep-proxy's test reads both into FileConfig and finds them equal, and the old names refused. zero-lab-k8s (values-pep.yaml) and every deployed openid-providers.yaml still have the old names and must change with the image that carries this. just check-changed in go/ passed.

The master's key (maintainer, 2026-11-16): master_jwk as a member of the configuration is gone. As a YAML mapping it went through an untyped map and back to JSON before the key parser saw it. KeyFiles.MasterJWKPath (master_jwk_path) names a file with the JWK as JSON; the host reads it like the other keys and hands it over as Keys.Master, which New takes as trust anchor where the program set no RelyingPartyConfig.FedMasterJWK. Jwk.UnmarshalYAML is removed. The loaders of zero-pdp and zero-pep-proxy read the file.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
oidf.FileConfig reads the same relying party from YAML and JSON with the names entity, master, master_entity_statement_uri and master_jwk_path (a file the host reads); old names are refused. Released as oidf v0.54.0 and pep/proxy v0.5.0; local config files renamed.
<!-- SECTION:FINAL_SUMMARY:END -->
