# Contributing

Thanks for being here.

This project is open source because open source works better than the
alternative. Contributions are welcome from anyone, at any experience level, on
anything from a typo fix to a feature you thought up yourself.

There is no bar to clear before you're allowed to participate. You don't need to
be invited, you don't need to have contributed before, and you don't need
permission to open an issue or a PR.

## Ways to help

**Report a bug.** Tell me what you did, what happened, and what you expected
instead. Version numbers and error output help a lot. If you can't reproduce it
reliably, say so and file it anyway.

**Ask for a feature.** Describe the problem you're trying to solve, not only the
solution you have in mind. There may be an easier path.

**Send a pull request.** Small ones get merged fast. Big ones are welcome too,
but open an issue first so you don't spend a weekend on something that's already
half finished in a branch somewhere.

**Fix the docs.** Docs PRs are real contributions. If something was confusing to
you, it was confusing to everyone who didn't say anything.

**Answer someone else's question.** Costs you five minutes, saves them an hour.

## Pull requests

Nothing exotic:

1. Fork and branch off the default branch.
2. Make the change.
3. Run whatever tests exist. If something was already broken before you touched
   it, mention that instead of quietly fixing it in the same PR.
4. Match the style of the code around you. If the repo has a linter or formatter
   config, use it.
5. Write a commit message that says what changed and why.
6. Open the PR and describe what it does.

Draft PRs are fine. Work in progress is fine. "I'm not sure this is the right
approach, thoughts?" is fine and is often the most useful kind of PR.

If your PR sits without a response, ping it. That isn't nagging, I probably lost
track of it. If I don't merge something I'll tell you why. It won't be personal
and it won't be silence.

## Ground rules

The only real rule is don't be a dick. That covers more ground than it sounds
like, so here are the parts that actually come up:

- Assume the other person is smart and acting in good faith. They usually are.
- Criticize code, not people. "This breaks on empty input" is useful. "Did you
  even test this?" is not.
- Nobody owes you a response, a fix, or a merge. That includes me owing you
  those, and it includes you owing them to anyone else.
- Don't gatekeep. No "you should already know this," no "just read the source,"
  no making someone feel stupid for asking a beginner question. Everyone was new
  once and most of us still are about something.
- No harassment, slurs, or personal attacks, and no hostility about anyone's
  identity, background, or experience level. That gets you removed and I won't
  lose sleep over it.
- When a thread starts going in circles, let it go. Nobody has ever won a GitHub
  argument.

Enforcement isn't a process, it's just me. If someone is being a problem, open an
issue or email archon@lockewerks.com. I'll deal with it, and I'll err on the side
of the person getting treated badly.

## Development

Use Windows 11 and the stable Rust MSVC toolchain. PowerShell 7 is needed for
provider-backed tools and the installer script. Native functionality requires
the corresponding installed Windows provider and actual token permissions.
Do not enable optional features or change system configuration just to make
a test pass.

```powershell
cargo check -j1 --tests
cargo test -j1
cargo clippy -j1 --all-targets -- -D warnings
```

Prefer the smallest relevant existing test selector while developing. For the
diagnostics unit tests and disposable native fixtures:

```powershell
cargo test -j1 --bin MasterControlProgram diagnostics:: -- --include-ignored --test-threads=1
```

Do not run every ignored test against a working desktop indiscriminately.
Read each fixture's prerequisites and use disposable targets. Subprocess helper
tests must remain inert when a broad test command selects them without their
explicit activation conditions.

## Code and documentation layout

| Area | Location |
|------|----------|
| Base tools and router composition | `src/server.rs` |
| Audio provider tools | `src/provider_tools.rs`, `src/win32/audio.rs` |
| Desktop, windows, UI Automation and OCR | `src/desktop.rs`, `src/desktop/` |
| ConPTY terminals and owned jobs | `src/execution.rs`, `src/execution/` |
| Watches, waits and ETW | `src/observation.rs`, `src/observation/` |
| Deterministic workflows | `src/workflow.rs`, `src/workflow/` |
| File/service editing | `src/system_control.rs`, `src/win32/filesystem.rs`, `src/win32/service.rs` |
| Network, virtualization, devices and storage | `src/administration.rs`, `src/win32/` |
| Process diagnostics and debugger actors | `src/diagnostics.rs`, `src/diagnostics/` |
| Local host, connection cleanup and identity | `src/host.rs`, `src/host/`, `src/connection.rs`, `src/context.rs` |
| General native runtime and PowerShell pool | `src/runtime.rs`, `src/ps/` |
| MCP integration tests | `tests/mcp.rs` |
| User documentation | [README.md](README.md), [control guide](docs/control-guide.md) |

A tool added to a separate named router must be included in the composed
router in `src/server.rs`. Updating only the original router does not cover
every tool family.

Preserve exact-target preconditions and numeric-string coercion where used.
Distinguish native acceptance from observed completion. Bound work and output,
report partial failures, and balance only the handles, suspensions and process
trees the operation owns. Cancellation must not silently retry a mutation.
Connection cleanup and explicitly persistent-host behavior need separate cases.

When changing a tool contract, update its schema description, the README catalog
and the relevant control-guide section. Document identity requirements, lifetime,
partial outcomes and unsupported cases. Do not infer current performance from
old PowerShell timings or advertise unimplemented operations.

## Release workflow

CI builds the release binary and runs clippy on pushes to `master`, pull
requests and explicit dispatches. It does not run the native test suite, so run
the relevant tests before publishing a code change.

Keep the package version in `Cargo.toml`/`Cargo.lock` and the product version in
`installer.toml` aligned. A pushed `v*` tag triggers the existing release
workflow: build the server, sign it, build the Forge installer from the signed
payload, sign the installer, verify both signatures and the installer container,
then publish both executable assets.

An explicit dispatch of the release workflow uploads artifacts without
publishing a GitHub release. Source builds and `install.ps1` do not sign binaries.
Do not put signing credentials in source, logs or documentation.

## Licensing

By contributing you agree your contribution is licensed under the same terms as
the project, whatever the LICENSE file says. There's no CLA and there won't be.
You don't sign anything over.

## Credit

Contributors get credit. If you'd rather not be listed, say so and you won't be.
