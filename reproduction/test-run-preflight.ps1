[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$runScript = Join-Path $PSScriptRoot 'run.ps1'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'eip0045-run-preflight-' + [Guid]::NewGuid().ToString('N')
)
$junctionRoot = $null
$substDrive = $null

function Invoke-Preflight(
    [string]$TargetRoot,
    [string]$Lane,
    [int]$MinimumFreeGiB
) {
    $savedTarget = $env:EIP0045_TARGET_DIR
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $env:EIP0045_TARGET_DIR = $TargetRoot
        $ErrorActionPreference = 'Continue'
        $output = @(
            & powershell -NoProfile -ExecutionPolicy Bypass -File $runScript `
                preflight -Lane $Lane -MinimumFreeGiB $MinimumFreeGiB 2>&1 |
                ForEach-Object { "$_" }
        )
        return [pscustomobject]@{
            ExitStatus = [int]$LASTEXITCODE
            Output = [string[]]$output
        }
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
        if ($null -eq $savedTarget) {
            Remove-Item Env:EIP0045_TARGET_DIR -ErrorAction SilentlyContinue
        } else {
            $env:EIP0045_TARGET_DIR = $savedTarget
        }
    }
}

function Invoke-EnvironmentPreflight(
    [string]$TargetRoot,
    [string]$Lane,
    [string]$MinimumFreeGiB
) {
    $savedTarget = $env:EIP0045_TARGET_DIR
    $savedLane = $env:EIP0045_TARGET_LANE
    $savedMinimum = $env:EIP0045_MIN_FREE_GIB
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $env:EIP0045_TARGET_DIR = $TargetRoot
        $env:EIP0045_TARGET_LANE = $Lane
        $env:EIP0045_MIN_FREE_GIB = $MinimumFreeGiB
        $ErrorActionPreference = 'Continue'
        $output = @(
            & powershell -NoProfile -ExecutionPolicy Bypass -File $runScript preflight 2>&1 |
                ForEach-Object { "$_" }
        )
        return [pscustomobject]@{
            ExitStatus = [int]$LASTEXITCODE
            Output = [string[]]$output
        }
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
        foreach ($binding in @(
            @('EIP0045_TARGET_DIR', $savedTarget),
            @('EIP0045_TARGET_LANE', $savedLane),
            @('EIP0045_MIN_FREE_GIB', $savedMinimum)
        )) {
            if ($null -eq $binding[1]) {
                Remove-Item -LiteralPath "Env:$($binding[0])" -ErrorAction SilentlyContinue
            } else {
                Set-Item -LiteralPath "Env:$($binding[0])" -Value $binding[1]
            }
        }
    }
}

function Assert-Status([object]$Result, [int]$Expected, [string]$Label) {
    if ($Result.ExitStatus -ne $Expected) {
        throw "$Label returned $($Result.ExitStatus), expected $($Expected):`n$($Result.Output -join "`n")"
    }
}

function Assert-OutputContains([object]$Result, [string]$Needle, [string]$Label) {
    if (($Result.Output -join "`n") -notlike "*$Needle*") {
        throw "$Label did not contain '$Needle':`n$($Result.Output -join "`n")"
    }
}

function Remove-DirectoryAlias([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -Force -LiteralPath $Path
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
        throw "refusing to remove a non-alias test path: $Path"
    }
    [System.IO.Directory]::Delete($Path, $false)
}

function Get-UnusedDosDrive() {
    foreach ($codePoint in 90..68) {
        $candidate = "$([char]$codePoint):"
        if (-not (Test-Path -LiteralPath "$candidate\")) {
            return $candidate
        }
    }
    throw 'no unused DOS drive letter is available for the alias regression'
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $successRoot = Join-Path $testRoot 'success'
    $success = Invoke-Preflight $successRoot 'h0-consumer' 0
    Assert-Status $success 0 'successful isolated-lane preflight'
    $expectedTarget = [System.IO.Path]::GetFullPath((Join-Path $successRoot 'h0-consumer'))
    Assert-OutputContains $success 'schema=eip0045-local-run-preflight-v1' 'successful preflight'
    Assert-OutputContains $success "targetDir=$expectedTarget" 'successful preflight'
    Assert-OutputContains $success 'lane=h0-consumer' 'successful preflight'

    $insideRepo = Invoke-Preflight (Join-Path $repoRoot '.preflight-test-target') 'inside' 0
    Assert-Status $insideRepo 1 'in-repository target rejection'
    Assert-OutputContains $insideRepo 'target directory overlaps the synchronized repository' 'in-repository target rejection'

    $savedCargoHome = $env:CARGO_HOME
    try {
        $env:CARGO_HOME = Join-Path $repoRoot '.preflight-test-cargo-home'
        $insideCargoHome = Invoke-Preflight (Join-Path $testRoot 'cargo-home') 'cargo-home' 0
    } finally {
        if ($null -eq $savedCargoHome) {
            Remove-Item Env:CARGO_HOME -ErrorAction SilentlyContinue
        } else {
            $env:CARGO_HOME = $savedCargoHome
        }
    }
    Assert-Status $insideCargoHome 1 'in-workspace CARGO_HOME rejection'
    Assert-OutputContains $insideCargoHome 'CARGO_HOME overlaps the synchronized repository' 'in-workspace CARGO_HOME rejection'

    $junctionRoot = Join-Path $testRoot 'repo-junction'
    New-Item -ItemType Junction -Path $junctionRoot -Target $repoRoot | Out-Null
    try {
        $aliasedTarget = Invoke-Preflight (Join-Path $junctionRoot '.preflight-target') 'alias' 0
    } finally {
        Remove-DirectoryAlias $junctionRoot
    }
    Assert-Status $aliasedTarget 1 'reparse-point target rejection'
    Assert-OutputContains $aliasedTarget 'traverses a symlink, junction, or mount-point alias' 'reparse-point target rejection'

    $substDrive = Get-UnusedDosDrive
    & subst.exe $substDrive $repoRoot
    if ($LASTEXITCODE -ne 0) {
        throw "cannot create test DOS-device alias $substDrive"
    }
    $substTarget = Join-Path "$substDrive\" '.eip0045-preflight-subst-target'
    try {
        $substAlias = Invoke-Preflight $substTarget 'subst' 0
    } finally {
        foreach ($generatedDirectory in @((Join-Path $substTarget 'subst'), $substTarget)) {
            if (Test-Path -LiteralPath $generatedDirectory) {
                $children = @(Get-ChildItem -Force -LiteralPath $generatedDirectory)
                if ($children.Count -ne 0) {
                    throw "refusing to remove non-empty generated alias target: $generatedDirectory"
                }
                [System.IO.Directory]::Delete($generatedDirectory, $false)
            }
        }
        & subst.exe $substDrive /d
        if ($LASTEXITCODE -ne 0) {
            throw "cannot remove test DOS-device alias $substDrive"
        }
    }
    Assert-Status $substAlias 1 'DOS-device alias target rejection'
    Assert-OutputContains $substAlias 'target directory overlaps the synchronized repository' 'DOS-device alias target rejection'
    $substDrive = $null

    $lowCapacity = Invoke-Preflight (Join-Path $testRoot 'low-capacity') 'capacity' 1048576
    Assert-Status $lowCapacity 1 'capacity rejection'
    Assert-OutputContains $lowCapacity 'free space is below the configured minimum' 'capacity rejection'

    $invalidEnvironmentLane = Invoke-EnvironmentPreflight (Join-Path $testRoot 'env-lane') '../bad' '0'
    Assert-Status $invalidEnvironmentLane 1 'environment lane validation'
    Assert-OutputContains $invalidEnvironmentLane 'EIP0045_TARGET_LANE must be empty or match' 'environment lane validation'

    $invalidEnvironmentMinimum = Invoke-EnvironmentPreflight (Join-Path $testRoot 'env-minimum') 'valid' '1048577'
    Assert-Status $invalidEnvironmentMinimum 1 'environment minimum validation'
    Assert-OutputContains $invalidEnvironmentMinimum 'EIP0045_MIN_FREE_GIB must be a non-negative integer no greater than 1048576' 'environment minimum validation'

    $signedEnvironmentMinimum = Invoke-EnvironmentPreflight (Join-Path $testRoot 'env-signed-minimum') 'valid' '+1'
    Assert-Status $signedEnvironmentMinimum 1 'environment minimum decimal syntax'
    Assert-OutputContains $signedEnvironmentMinimum 'EIP0045_MIN_FREE_GIB must be a non-negative integer no greater than 1048576' 'environment minimum decimal syntax'

    $declaredSyncRoot = Join-Path $testRoot 'declared-sync-root'
    New-Item -ItemType Directory -Path $declaredSyncRoot | Out-Null
    $savedForbiddenRoots = $env:EIP0045_FORBIDDEN_SYNC_ROOTS
    try {
        $env:EIP0045_FORBIDDEN_SYNC_ROOTS = $declaredSyncRoot
        $declaredSyncTarget = Invoke-EnvironmentPreflight (Join-Path $declaredSyncRoot 'target') 'declared-sync' '0'
    } finally {
        if ($null -eq $savedForbiddenRoots) {
            Remove-Item Env:EIP0045_FORBIDDEN_SYNC_ROOTS -ErrorAction SilentlyContinue
        } else {
            $env:EIP0045_FORBIDDEN_SYNC_ROOTS = $savedForbiddenRoots
        }
    }
    Assert-Status $declaredSyncTarget 1 'declared synchronized-root rejection'
    Assert-OutputContains $declaredSyncTarget 'target directory overlaps the synchronized repository or workspace' 'declared synchronized-root rejection'

    $lockRoot = Join-Path $testRoot 'lock'
    $lockTarget = Join-Path $lockRoot 'same-lane'
    New-Item -ItemType Directory -Path $lockTarget | Out-Null
    $lockPath = Join-Path $lockTarget '.eip0045-run.lock'
    $heldLock = [System.IO.File]::Open(
        $lockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
    try {
        $parallel = Invoke-Preflight $lockRoot 'other-lane' 0
        Assert-Status $parallel 0 'distinct-lane parallel preflight'
        Assert-OutputContains $parallel 'lane=other-lane' 'distinct-lane parallel preflight'
        $contended = Invoke-Preflight $lockRoot 'same-lane' 0
    } finally {
        $heldLock.Dispose()
    }
    Assert-Status $contended 1 'same-lane contention rejection'
    Assert-OutputContains $contended 'target lane is already in use' 'same-lane contention rejection'

    Write-Output 'eip0045 run preflight tests: 12 passed'
} finally {
    if ($null -ne $substDrive -and (Test-Path -LiteralPath "$substDrive\")) {
        & subst.exe $substDrive /d
    }
    if ($null -ne $junctionRoot -and (Test-Path -LiteralPath $junctionRoot)) {
        Remove-DirectoryAlias $junctionRoot
    }
    if ($null -ne $junctionRoot -and (Test-Path -LiteralPath $junctionRoot)) {
        throw "refusing recursive test cleanup while junction remains: $junctionRoot"
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
