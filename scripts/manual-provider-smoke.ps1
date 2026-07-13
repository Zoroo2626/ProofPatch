param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("claude", "codex")]
    [string]$Provider,

    [Parameter(Mandatory = $true)]
    [string]$Repository,

    [Parameter(Mandatory = $true)]
    [string]$Config,

    [Parameter(Mandatory = $true)]
    [string]$Issue
)

$ErrorActionPreference = "Stop"
$credential = if ($Provider -eq "claude") { "ANTHROPIC_API_KEY" } else { "CODEX_API_KEY" }
if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($credential))) {
    throw "Set $credential in this process before running the protected smoke test."
}

& proofpatch run `
    --repository $Repository `
    --config $Config `
    --issue $Issue `
    --agent $Provider `
    --mode protected `
    --yes

if ($LASTEXITCODE -ne 0) {
    throw "The $Provider protected smoke test failed with exit code $LASTEXITCODE."
}
