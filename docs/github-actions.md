# GitHub Actions integration

Phase 9 provides a deterministic, secret-free pull-request action. It runs native verification,
writes the before/after result to the job summary, and uploads only the verified JSON and Markdown
receipts. Native execution is an observation mechanism, not a sandbox; use a GitHub-hosted
ephemeral runner and do not attach secrets to the verification job.

## Safe pull-request workflow

Replace both example ProofPatch references with one audited full commit SHA. The verification job
has read-only repository access, disables persisted Git credentials, and never references a
repository secret. Pull-request text is passed through an environment-backed action input and is
never interpolated into a shell program.

```yaml
name: ProofPatch

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    outputs:
      comment-body: ${{ steps.proofpatch.outputs.comment-body }}
    steps:
      - name: Check out the pull request merge commit
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Capture the PR patch and restore the baseline
        shell: bash
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          [[ "$BASE_SHA" =~ ^[0-9a-f]{40}$ ]]
          [[ "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]
          git diff --binary --full-index --no-ext-diff --no-textconv \
            "$BASE_SHA" "$HEAD_SHA" -- > "$RUNNER_TEMP/pull-request.diff"
          git checkout --detach "$BASE_SHA"

      - name: Prove the before-and-after behavior
        id: proofpatch
        uses: proofpatch/proofpatch@0123456789abcdef0123456789abcdef01234567
        with:
          repository: .
          patch-file: ${{ runner.temp }}/pull-request.diff
          baseline-command: python reproduce.py
          regression-command: python -m pytest
          issue: ${{ github.event.pull_request.body }}
```

The patch exists only in the ephemeral runner temporary directory. The upload step inside the
action names `receipt.json` and `receipt.md` individually; it never uploads the workspace, the
patch, logs, a glob, or ProofPatch's evidence directory. Receipts still contain issue text,
filenames, commit IDs, and hashes, so set an appropriate artifact retention period for private
projects.

## Optional PR comments

Commenting is deliberately a separate job. Enable it only for same-repository pull requests. This
job does not check out, download, or execute pull-request code and receives no provider credential.
Its only permission is `pull-requests: write`.

```yaml
  comment:
    needs: verify
    if: >-
      github.event.pull_request.head.repo.full_name == github.repository &&
      vars.PROOFPATCH_PR_COMMENTS == 'true'
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Comment with the sanitized result
        uses: proofpatch/proofpatch/.github/actions/comment@0123456789abcdef0123456789abcdef01234567
        with:
          token: ${{ github.token }}
          repository: ${{ github.repository }}
          pull-request-number: ${{ github.event.pull_request.number }}
          body: ${{ needs.verify.outputs.comment-body }}
```

Do not combine these jobs, pass `github.token` to the verification action, add secrets to the
verification job, or change the trigger to `pull_request_target`. A process executed by the
repository could otherwise persist on the runner and wait for a later privileged step.

## Fork behavior and protected agent runs

The basic `pull_request` workflow intentionally uses no secrets, so it has the same inputs for fork
and same-repository pull requests. GitHub withholds Actions secrets and downgrades the token for
fork pull requests, while the explicit same-repository condition prevents the comment job from
being attempted for a fork.

Full protected agent runs require provider credentials and must not be triggered by untrusted pull
request code. Run them only from a maintainer-controlled `workflow_dispatch` workflow that checks
out a trusted commit, or from another trusted system. Never use `pull_request_target` to check out
and execute a pull request, never enable the repository setting that sends secrets or write tokens
to fork workflows, and never run untrusted artifacts in a privileged follow-up workflow.

The integration does not emit SARIF. Phase 9 receipts describe a repository-specific behavioral
proof, not source locations with standardized static-analysis rules, so mapping these results to
SARIF would be misleading.
