# Welcome to the gematik contributing guide

Thank you for investing your time in contributing to zero-lab!

In this guide you will get an overview how you can contribute by opening an issue and by
creating a pull request. zero-lab is a research and proof-of-concept project:
contributions are welcome, but there is no commitment to review or merge them within a
given time.

## Reporting a security vulnerability

Please report vulnerabilities as described in the [Security Policy](./SECURITY.md).

## New contributor guide

To get an overview of the project, read the [README](./README.md). zero-lab builds trust
decisions for the Telematikinfrastruktur and is security-critical: every change is held
against the [principles](./docs/principles.md) and the binding rules in
[docs](./docs/README.md). Read the documents your change touches before you start, and
the development guide of the workspace you work in: [Rust](./rust/docs/development.md)
or [Go](./go/docs/development.md).

Each rule lives in exactly one document, and others link to it
([owning a rule](./docs/README.md#owning-a-rule)). The same holds for text written for
agents and scripts: how `ti` is used is described once, in
[`rust/ti-cli/AGENTS.md`](./rust/ti-cli/AGENTS.md), which every installed `ti` prints
with `ti agent`. Point agents there, or improve that file, rather than adding a second
copy of it. Skills and the rules agents follow with the tools are in
[text for agents](./docs/conventions/agents.md).

## Getting started

### Issues

#### Create a new issue

If you spot a problem or have a feature request, search if an
[issue](https://github.com/gematik/zero-lab/issues) already exists. If a related issue
doesn't exist, you can open a new issue.

#### Solve an issue

Work in this repository starts from a task in the [backlog](./docs/conventions/backlog.md).
Scan the open tasks in [`backlog/tasks`](./backlog/tasks) and the
issues for one that interests you. If your change has no task yet, open an issue first
and describe what you want to change and why; the maintainer creates the task, and your
pull request names it.

### Make changes

1. Fork the repository and create a branch from `main`, named as described in
   [git and releases](./docs/conventions/git-and-releases.md#branches-and-pull-requests).
2. Work inside the workspace you change, as its development guide describes.
3. Ask in the issue before adding a dependency or a feature that pulls new ones, with the
   reason, the transitive cost and the alternatives
   ([dependencies](./docs/conventions/dependencies.md)).
4. Run the checks of each workspace you changed: `just check` in `rust/` and in `go/`.
5. Start every new source file with the EUPL-1.2 license header its neighbours use,
   beginning with `Copyright (Change Date see Readme), gematik GmbH`.
6. Add your change to the release notes of its workspace
   ([release notes](./docs/conventions/git-and-releases.md#release-notes)).

### Commit your update

Commit the changes once you are happy with them, following the
[commit conventions](./docs/conventions/git-and-releases.md#commits).

### Pull Request Process

- When you're finished with the changes, open a pull request against `main`.
- Say what changed, why, and how it was verified (the checks that ran and their result),
  and name the backlog task or issue it completes. A change that falls short of a
  [principle](./docs/principles.md) says so.
- Once you submit your PR, the maintainer will review your proposal. We may ask questions
  or request additional information.
- We may ask for changes to be made before a PR can be merged, either using
  [suggested changes](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/incorporating-feedback-in-your-pull-request)
  or pull request comments. You can make any changes in your fork, then commit them to
  your branch.
- As you update your PR and apply changes, mark each conversation as
  [resolved](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/commenting-on-a-pull-request#resolving-conversations).
- The maintainer merges approved pull requests; nobody merges their own.

By submitting a contribution, you agree that it is licensed under the
[EUPL-1.2](./LICENSE).

### Your PR is merged!

Congratulations :tada: The gematik team thanks you :sparkles:.

Once your PR is merged, your contributions will be publicly visible on the
[gematik GitHub page](https://github.com/gematik/).
