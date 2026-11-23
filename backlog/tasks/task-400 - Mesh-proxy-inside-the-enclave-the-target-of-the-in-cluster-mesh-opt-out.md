---
id: TASK-400
title: 'Mesh proxy inside the enclave: the target of the in-cluster mesh opt-out'
status: Done
assignee: []
created_date: 2026-11-19 15:20
updated_date: '2026-11-23T22:04:00Z'
labels:
  - servers
  - transport
  - kubernetes
dependencies:
  - TASK-399
references:
  - docs/design/servers.md
priority: low
ordinal: 413000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md rule 29 (TASK-399) allows http:// inside the cluster with a declared mesh wherever its proxy runs, as the state for now. The target is a mesh proxy inside the enclave, in the pod and measured with it (rule 7), so that the channel ends inside the TCB (rule 5). To find out: which meshes can run their proxy as a native sidecar in a confidential pod and have its image in the pod policy that attestation measures (Istio ambient vs sidecar mode, Linkerd), what the deployments here use, and when the rule can drop 'wherever its proxy runs'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 For each mesh a deployment here uses, it is recorded whether and how its proxy runs inside the enclave and is measured
- [x] #2 Rule 29 drops the transitional allowance, or records why it stays
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-20: rule 29 no longer names a mesh: the operator accepts plaintext with …_PLAINTEXT_ACCEPTED=true, and the target reads 'the protecting proxy inside the enclave'.

2026-11-23. Deployments here: zero-lab-k8s (zerobin) has no mesh and no confidential runtime; gematik's ZETA Guard charts (../zeta/zeta-guard-helm) render Istio PeerAuthentication STRICT when global.istio.enabled (default false) and leave the data plane mode open; gemSpec_ZETA V1.3.2 recommends Istio, Linkerd or Cilium (A_28781, A_26519) and keeps PrK.K8s.mTLS 'innerhalb der VAU'. Per mesh: Istio ambient: ztunnel per node, 'another trust boundary', holds the keys of every pod on the node (istio.io security model): never inside the enclave. Cilium WireGuard/IPsec: node keys, channel ends on the host: never. Istio sidecar: in the pod, but in Kata the CNI redirect lands in the host netns and the guest bypasses it, the agent policy denies SetIPTablesRequest (kata-containers#14137, open, maintainers agreed 2026-11-10 to fix the rego); a webhook-injected sidecar must be in the generated policy (kata#9220, Red Hat 'debug confidential containers'). Linkerd: native sidecar by default since 2.20, same open questions, no CoCo report found. Contrast: Envoy sidecar added by contrast generate, policy over every container by image digest bound via initdata to HOSTDATA/MRCONFIGID, mesh certificate only after attestation: meets the target (the docs do not state the order of injection and policy generation word for word).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Rule 29 now records which mesh proxies can meet the target inside the enclave (a sidecar in the confidential pod whose image the measured policy names and whose redirection happens in the guest, e.g. Contrast's mesh; never a node proxy such as Istio ambient or Cilium) and keeps the plaintext allowance while no deployment runs confidential, dropping it with the first that does. Per-mesh findings with sources in the notes.
<!-- SECTION:FINAL_SUMMARY:END -->
