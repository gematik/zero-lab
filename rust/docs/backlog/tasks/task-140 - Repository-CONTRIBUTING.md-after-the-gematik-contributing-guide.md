---
id: TASK-140
title: 'Repository: CONTRIBUTING.md after the gematik contributing guide'
status: Done
assignee: []
created_date: '2026-10-26 10:05'
updated_date: '2026-10-26 10:26'
labels:
  - chore
  - docs
dependencies: []
priority: low
ordinal: 149000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
CONTRIBUTING.md is a short list that predates docs/: it does not say that work starts from a backlog task, what a pull request must state (docs/conventions/git-and-releases.md), that each rule and each agent-facing text lives in one document (docs/README.md, ti-cli/AGENTS.md served by `ti agent`), nor how an external contributor without the backlog CLI gets a task. PR #75 showed the gap: an agent skill duplicating AGENTS.md, without a task or release-notes entry. The maintained gematik repositories (api-telematik, publish-tools, E-Rezept-App-Android) share one contributing guide; zero-lab follows its structure, adapted to the rules in docs/, and links to them instead of restating them.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 CONTRIBUTING.md follows the sections of the gematik contributing guide: security, new contributor guide, issues, pull request process, merged
- [x] #2 It links to the rules in docs/ and the development guides and restates none of them
- [x] #3 It says how external contributors get a backlog task and what a pull request states (what, why, how verified, release-notes entry)
- [x] #4 It names ti-cli/AGENTS.md, served by `ti agent`, as the one place for agent-facing documentation of ti
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Template: the shared gematik contributing guide (api-telematik, publish-tools, E-Rezept-App-Android; zeta and OpenHealth-Core differ: Jira, Apache-2.0). Kept its sections; replaced the generic steps (version bump, two sign-offs, PR template) with links to docs/conventions, since zero-lab versions by tag and the maintainer merges. External contributors without the backlog CLI open an issue, the maintainer creates the task.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
CONTRIBUTING.md now follows the shared gematik contributing guide (api-telematik, publish-tools, E-Rezept-App-Android): security, new contributor guide, issues, changes, commits, pull request process. It links to docs/ instead of restating rules; external contributors get their backlog task through an issue; a PR states what, why, how verified and its task; agent-facing text of ti lives only in rust/ti-cli/AGENTS.md (ti agent). Verified the relative links and anchors exist. Committed directly to main at the maintainer's request.
<!-- SECTION:FINAL_SUMMARY:END -->
