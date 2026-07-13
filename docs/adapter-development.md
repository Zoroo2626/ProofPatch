# Agent Adapter Development

ProofPatch supports three reviewed adapters: `generic`, `claude`, and `codex`. An adapter returns
only a structured argument vector, an explicit environment mapping, and expected output paths. It
cannot return mounts, Docker options, network settings, state transitions, evidence events, or
verification results. The controller owns all of those decisions.

## Shared boundary

Provider commands run in the same protected Docker backend as the generic adapter. Investigation
source is read-only; patch source is an independent writable clone; prompts and issue text are
controller-authored read-only files. No adapter mounts a host home, provider configuration or
session directory, original repository, evidence directory, or Docker socket. Provider stdout and
stderr are bounded, secret-redacted by the backend, stored privately, and hash-referenced in
evidence. A transcript or provider exit code never proves a fix.

Provider configuration accepts only the executable as `agent.command`. Additional command-line
flags are rejected because they could re-enable sessions, add directories, load plugins, or bypass
permissions. ProofPatch supplies the reviewed flags. Credentials must be present in the process
environment and named exactly in `environment_allowlist`; values are selected at runtime and are
never serialized into the resolved workflow plan.

## Claude Code

Minimum tested CLI: `2.1.201`. Version detection uses `claude --version` in a separate protected,
credential-free, network-disabled container before investigation.

The adapter uses print mode with JSON output, text input, no session persistence, bare mode, the
`acceptEdits` permission mode, and the controller prompt passed with `--system-prompt-file`. Bare
mode prevents automatic discovery of hooks, skills, plugins, MCP, memory, and `CLAUDE.md`. It is
intentionally paired only with `ANTHROPIC_API_KEY`: current Claude documentation states that bare
mode does not read `CLAUDE_CODE_OAUTH_TOKEN`.

```yaml
agent:
  adapter: claude
  command: ["claude"]
  environment_allowlist: ["ANTHROPIC_API_KEY"]
```

ProofPatch never uses `--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions`, or
the `bypassPermissions` mode. Claude may process repository, issue, prompt, and approved
reproduction-asset content through Anthropic's service under the user's account and agreement.
ProofPatch does not send its evidence store or original repository.

Official behavior checked July 13, 2026: [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage)
and [Claude Code authentication](https://code.claude.com/docs/en/authentication).

## Codex CLI

Minimum tested CLI: `0.139.0`. Version detection uses `codex --version` under the same isolated
probe rules.

The adapter uses stable `codex exec`, newline-delimited JSON output, ephemeral sessions, no user
configuration, no repository exec-policy rules, no ANSI color, and an explicit working directory.
Its inner sandbox is `read-only` for investigation and `workspace-write` for patching. This inner
sandbox is defense in depth only; ProofPatch's Docker policy remains the outer enforcement
boundary. The only accepted credential is `CODEX_API_KEY`, documented for a single noninteractive
run.

```yaml
agent:
  adapter: codex
  command: ["codex"]
  environment_allowlist: ["CODEX_API_KEY"]
```

ProofPatch never passes `--add-dir`, `--dangerously-bypass-approvals-and-sandbox`, `--yolo`,
`danger-full-access`, or the deprecated `--full-auto`. Codex may process repository, issue, prompt,
and approved reproduction-asset content through OpenAI's service under the user's account and
agreement. ProofPatch does not send its evidence store or original repository.

Official behavior checked July 13, 2026: [Codex non-interactive mode](https://learn.chatgpt.com/codex/non-interactive-mode),
[Codex CLI reference](https://learn.chatgpt.com/docs/developer-commands?surface=cli), and
[Codex environment variables](https://learn.chatgpt.com/codex/config-file/environment-variables).

## Generic adapter

The generic command supports only `{prompt_path}`, `{workspace_path}`, `{output_path}`,
`{reproduction_path}`, and `{issue_path}`. Unknown placeholders, conversions, format specifiers,
empty arguments, shell strings, and non-allowlisted environment names are rejected. Generic
commands do not have a provider version probe because ProofPatch cannot safely infer an arbitrary
CLI's version interface.

For every adapter, investigation authorization comes only from a validated contract independently
reproduced by ProofPatch. Patch authorization comes only from an exact captured diff that passes
fresh verification.
