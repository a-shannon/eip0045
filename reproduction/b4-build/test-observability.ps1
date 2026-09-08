$ErrorActionPreference = 'Stop'

$helper = Join-Path $PSScriptRoot 'native-command.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    throw "missing B4 native-command helper: $helper"
}
. $helper

function Invoke-B4ContainerGuardFixture([string]$Root) {
    $diagnostics = Join-Path $Root 'diagnostics'
    $staging = Join-Path $Root 'staging'
    [System.IO.Directory]::CreateDirectory($diagnostics) | Out-Null
    [System.IO.Directory]::CreateDirectory($staging) | Out-Null

    Initialize-B4ContainerGuard
    Start-B4ContainerGuard -Name 'eip0045-guard-fixture' -DiagnosticRoot $diagnostics
    $removeBeforeInspectRejected = $false
    try {
        Complete-B4ContainerRemoval -Name 'eip0045-guard-fixture'
    } catch {
        $removeBeforeInspectRejected = $true
    }
    if (-not $removeBeforeInspectRejected) { throw 'container guard allowed removal before inspection' }

    Write-B4ContainerUncertainty -Reason 'post-run-inspection-failed'
    if (-not (Test-B4ContainerBindSourcesMustRemain)) {
        throw 'container guard did not preserve bind sources after an uncertain run'
    }
    if (-not (Test-Path -LiteralPath $staging -PathType Container)) {
        throw 'container guard moved its staging fixture'
    }

    Set-B4ContainerInspected -Name 'eip0045-guard-fixture'
    if (-not (Test-B4ContainerBindSourcesMustRemain)) {
        throw 'inspection alone cleared bind-source preservation'
    }
    Complete-B4ContainerRemoval -Name 'eip0045-guard-fixture'
    if (Test-B4ContainerBindSourcesMustRemain) {
        throw 'inspect plus successful removal did not clear bind-source preservation'
    }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("eip0045-b4-ps-observability-" + [Guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $child = Join-Path $testRoot 'native-child.ps1'
    [System.IO.File]::WriteAllText(
        $child,
        @'
param(
    [int]$ExitStatus,
    [string]$Stdout,
    [string]$Stderr,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Remaining
)
if ($Stdout) { [Console]::Out.Write($Stdout) }
if ($Remaining.Count -ne 0) { [Console]::Out.Write(($Remaining -join '|')) }
if ($Stderr) { [Console]::Error.Write($Stderr) }
exit $ExitStatus
'@,
        [System.Text.UTF8Encoding]::new($false)
    )
    $nativePowerShell = (Get-Process -Id $PID).Path

    $captured = Invoke-B4NativeCapture -FilePath $nativePowerShell -Arguments @(
        '-NoProfile', '-File', $child,
        '-ExitStatus', '37', '-Stdout', 'stdout:', '-Stderr', 'diagnostic-stderr',
        'alpha beta', 'comma,value'
    )
    if ($captured.ExitStatus -ne 37) { throw "capture changed exit status: $($captured.ExitStatus)" }
    $capturedText = $captured.Output -join "`n"
    if ($capturedText -notlike '*stdout:alpha beta|comma,value*' -or $capturedText -notlike '*diagnostic-stderr*') {
        throw "capture lost native output or argument boundaries: $capturedText"
    }
    if ($ErrorActionPreference -ne 'Stop') { throw 'capture did not restore ErrorActionPreference' }

    $discarded = Invoke-B4NativeCapture -FilePath $nativePowerShell -Arguments @(
        '-NoProfile', '-File', $child, '-ExitStatus', '23', '-Stderr', 'discarded-stderr'
    ) -Discard
    if ($discarded.ExitStatus -ne 23 -or $discarded.Output.Count -ne 0) {
        throw 'discard mode did not preserve status while suppressing output'
    }
    if ($ErrorActionPreference -ne 'Stop') { throw 'discard mode did not restore ErrorActionPreference' }

    $passthroughStatus = 0
    Invoke-B4NativePassthrough -FilePath $nativePowerShell -Arguments @(
        '-NoProfile', '-File', $child, '-ExitStatus', '19'
    ) -ExitStatus ([ref]$passthroughStatus)
    if ($passthroughStatus -ne 19) { throw "passthrough changed exit status: $passthroughStatus" }
    if ($ErrorActionPreference -ne 'Stop') { throw 'passthrough did not restore ErrorActionPreference' }

    $hardLinkRoot = Join-Path $testRoot 'hard-link-fixture'
    [System.IO.Directory]::CreateDirectory($hardLinkRoot) | Out-Null
    $hardLinkTarget = Join-Path $hardLinkRoot 'target.txt'
    $hardLinkAlias = Join-Path $hardLinkRoot 'alias.txt'
    [System.IO.File]::WriteAllText(
        $hardLinkTarget,
        "fixture`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    New-Item -ItemType HardLink -Path $hardLinkAlias -Target $hardLinkTarget | Out-Null
    if ((Get-B4WindowsHardLinkCount $hardLinkTarget) -ne 2) {
        throw 'Windows hard-link count oracle did not observe both fixture names'
    }
    $hardLinkRejected = $false
    try {
        Assert-B4NoDescendantHardLink $hardLinkRoot 'hard-link fixture'
    } catch {
        $hardLinkRejected = $_.Exception.Message -like '*exactly one hard link*'
    }
    if (-not $hardLinkRejected) { throw 'Windows input preflight admitted a hard-linked file' }

    $gitSource = Join-Path $testRoot 'git-source'
    $gitClone = Join-Path $testRoot 'git-standalone'
    $gitWorktree = Join-Path $testRoot 'git-worktree'
    foreach ($invocation in @(
        @('init', '--initial-branch=main', $gitSource),
        @('-C', $gitSource, 'config', 'user.name', 'B4 Test'),
        @('-C', $gitSource, 'config', 'user.email', 'b4-test@example.invalid')
    )) {
        $gitResult = Invoke-B4NativeCapture -FilePath 'git' -Arguments $invocation -Discard
        if ($gitResult.ExitStatus -ne 0) { throw "Git fixture setup failed: $($invocation -join ' ')" }
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $gitSource 'fixture.txt'),
        "fixture`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    foreach ($invocation in @(
        @('-C', $gitSource, 'add', '--', 'fixture.txt'),
        @('-C', $gitSource, 'commit', '-m', 'fixture'),
        @('clone', '--no-local', $gitSource, $gitClone)
    )) {
        $gitResult = Invoke-B4NativeCapture -FilePath 'git' -Arguments $invocation -Discard
        if ($gitResult.ExitStatus -ne 0) { throw "Git fixture setup failed: $($invocation -join ' ')" }
    }
    Assert-B4StandaloneGitCheckout $gitClone

    $gitResult = Invoke-B4NativeCapture -FilePath 'git' -Arguments @(
        '-C', $gitClone, 'worktree', 'add', '--detach', $gitWorktree, 'HEAD'
    ) -Discard
    if ($gitResult.ExitStatus -ne 0) { throw 'Git worktree fixture setup failed' }
    $worktreeRejected = $false
    try {
        Assert-B4StandaloneGitCheckout $gitWorktree
    } catch {
        $worktreeRejected = $_.Exception.Message -like '*standalone .git directory*'
    }
    if (-not $worktreeRejected) { throw 'B4 checkout preflight admitted a linked worktree' }

    $alternates = Join-Path $gitClone '.git\objects\info\alternates'
    [System.IO.File]::WriteAllText($alternates, '', [System.Text.UTF8Encoding]::new($false))
    $alternatesRejected = $false
    try {
        Assert-B4StandaloneGitCheckout $gitClone
    } catch {
        $alternatesRejected = $_.Exception.Message -like '*alternates metadata*'
    }
    if (-not $alternatesRejected) { throw 'B4 checkout preflight admitted Git alternates metadata' }
    Remove-Item -LiteralPath $alternates -Force

    $savedGitIndex = [Environment]::GetEnvironmentVariable('GIT_INDEX_FILE', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('GIT_INDEX_FILE', 'forbidden-index', 'Process')
        $overrideRejected = $false
        try {
            Assert-B4StandaloneGitCheckout $gitClone
        } catch {
            $overrideRejected = $_.Exception.Message -like '*forbids inherited GIT_INDEX_FILE*'
        }
        if (-not $overrideRejected) { throw 'B4 checkout preflight admitted a Git environment override' }
    } finally {
        [Environment]::SetEnvironmentVariable('GIT_INDEX_FILE', $savedGitIndex, 'Process')
    }

    $guardFirst = Join-Path $testRoot 'guard-first'
    $guardSecond = Join-Path $testRoot 'guard-second'
    Invoke-B4ContainerGuardFixture $guardFirst
    Invoke-B4ContainerGuardFixture $guardSecond
    $firstUncertainty = [System.IO.File]::ReadAllText(
        (Join-Path $guardFirst 'diagnostics\container-presence-uncertain.txt')
    )
    $secondUncertainty = [System.IO.File]::ReadAllText(
        (Join-Path $guardSecond 'diagnostics\container-presence-uncertain.txt')
    )
    if ($firstUncertainty -cne $secondUncertainty) {
        throw 'container uncertainty diagnostics are not deterministic'
    }
    foreach ($requiredLine in @(
        'schema=eip0045-b4-host-container-presence-v1',
        'containerName=eip0045-guard-fixture',
        'state=possible',
        'reason=post-run-inspection-failed',
        'bindSourcesPreserved=true',
        'removalConfirmed=false'
    )) {
        if (($firstUncertainty -split "`n") -cnotcontains $requiredLine) {
            throw "container uncertainty diagnostic lost: $requiredLine"
        }
    }

    $interruptedRoot = Join-Path $testRoot 'guard-interrupted'
    $interruptedDiagnostics = Join-Path $interruptedRoot 'diagnostics'
    $interruptedStaging = Join-Path $interruptedRoot 'staging'
    [System.IO.Directory]::CreateDirectory($interruptedDiagnostics) | Out-Null
    [System.IO.Directory]::CreateDirectory($interruptedStaging) | Out-Null
    Initialize-B4ContainerGuard
    Start-B4ContainerGuard -Name 'eip0045-guard-interrupt' -DiagnosticRoot $interruptedDiagnostics
    try {
        throw 'simulated runner interruption'
    } catch {
        Write-B4ContainerUncertainty -Reason 'runner-exited-before-removal-confirmed'
        if (-not (Test-B4ContainerBindSourcesMustRemain)) { throw }
    }
    if (-not (Test-Path -LiteralPath $interruptedStaging -PathType Container)) {
        throw 'interruption handling moved an uncertain bind source'
    }
    Set-B4ContainerInspected -Name 'eip0045-guard-interrupt'
    Complete-B4ContainerRemoval -Name 'eip0045-guard-interrupt'
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Output "B4 PowerShell observability ($($PSVersionTable.PSVersion)): passed"
