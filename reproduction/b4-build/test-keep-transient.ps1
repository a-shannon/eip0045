[CmdletBinding()]
param([Parameter(Mandatory)][string]$ResultRoot)

$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '..\b4-build.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    [System.IO.Path]::GetFullPath($source), [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'B4 source does not parse' }
foreach ($name in @('Fail', 'Test-PathAlias', 'Assert-NoDescendantPathAlias', 'Remove-OwnedTransientRoot')) {
    $definition = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if ($definition.Count -ne 1) { throw "missing exact source function: $name" }
    Invoke-Expression $definition[0].Extent.Text
}
$main = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.TryStatementAst]
})
if ($main.Count -ne 1 -or $main[0].CatchClauses.Count -ne 1 -or $null -eq $main[0].Finally) {
    throw 'missing exact source catch/finally'
}

if (-not [System.IO.Path]::IsPathRooted($ResultRoot)) { throw 'fixture root must be absolute' }
$root = [System.IO.Path]::GetFullPath($ResultRoot)
if (Test-Path -LiteralPath $root) { throw 'fixture root must be fresh' }
[System.IO.Directory]::CreateDirectory($root) | Out-Null
$parent = Join-Path $root 'parent'
[System.IO.Directory]::CreateDirectory($parent) | Out-Null
$output = [pscustomobject]@{Parent=$parent;Name='final';Path=(Join-Path $parent 'final')}
$workRoot = Join-Path $parent '.final.b4-work.fixture'
$stagingRoot = Join-Path $parent '.final.b4-staging.fixture'
$unownedRoot = Join-Path $parent 'unowned.fixture'
foreach ($path in @($workRoot, $stagingRoot, $unownedRoot)) {
    [System.IO.Directory]::CreateDirectory($path) | Out-Null
    $marker = Join-Path $path 'marker.bin'
    $stream = [System.IO.File]::Open($marker, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.WriteByte(42) } finally { $stream.Dispose() }
}

$script:removeCalls = [System.Collections.Generic.List[string]]::new()
function Remove-Item {
    param([string]$LiteralPath, [switch]$Recurse, [switch]$Force)
    if (-not $Recurse -or -not $Force) { throw 'unexpected legacy cleanup invocation' }
    $script:removeCalls.Add($LiteralPath)
}
function Test-B4ContainerBindSourcesMustRemain { return $false }
function Assert-Equal($Actual, $Expected, [string]$Label) {
    if ($Actual -cne $Expected) { throw "${Label}: expected '$Expected', got '$Actual'" }
}
function Assert-Retained([string]$Path) {
    if (-not (Test-Path -LiteralPath (Join-Path $Path 'marker.bin') -PathType Leaf)) {
        throw "fixture was removed or moved: $Path"
    }
}
$passes = [System.Collections.Generic.List[string]]::new()

$workMessage = @(Remove-OwnedTransientRoot $workRoot $parent $output.Name 'work' -Keep)
$stagingMessage = @(Remove-OwnedTransientRoot $stagingRoot $parent $output.Name 'staging' -Keep)
Assert-Equal $workMessage.Count 1 'work message count'
Assert-Equal $stagingMessage.Count 1 'staging message count'
if ($workMessage[0] -cnotmatch 'work transient directory retained at ' -or
    $stagingMessage[0] -cnotmatch 'staging transient directory retained at ') { throw 'retention message missing' }
Assert-Retained $workRoot
Assert-Retained $stagingRoot
Assert-Equal $script:removeCalls.Count 0 'keep delete calls'
$passes.Add('keep-preserves-work-and-staging')

$null = Remove-OwnedTransientRoot $workRoot $parent $output.Name 'work'
Assert-Equal $script:removeCalls.Count 1 'legacy cleanup call count'
Assert-Equal $script:removeCalls[0] $workRoot 'legacy cleanup target'
Assert-Retained $workRoot # The mock, not production, leaves the fixture in place.
$passes.Add('default-uses-legacy-cleanup')

foreach ($keep in @($false, $true)) {
    try {
        Remove-OwnedTransientRoot $unownedRoot $parent $output.Name 'work' -Keep:$keep | Out-Null
        throw 'unowned path was admitted'
    } catch {
        if ($_.Exception.Message -notmatch 'refusing to clean an unowned transient directory') { throw }
    }
}
Assert-Equal $script:removeCalls.Count 1 'unowned delete calls'
$passes.Add('ownership-guard-both-modes')

$originalAlias = (Get-Item Function:Test-PathAlias).ScriptBlock
function Test-PathAlias { param($Item) return $true }
try {
    Remove-OwnedTransientRoot $workRoot $parent $output.Name 'work' -Keep | Out-Null
    throw 'aliased root was admitted'
} catch {
    if ($_.Exception.Message -notmatch 'refusing to clean aliased transient directory') { throw }
} finally { Set-Item Function:Test-PathAlias $originalAlias }
Assert-Equal $script:removeCalls.Count 1 'alias delete calls'
$passes.Add('alias-guard-before-retention')

$originalDescendants = (Get-Item Function:Assert-NoDescendantPathAlias).ScriptBlock
function Assert-NoDescendantPathAlias { throw 'fixture descendant alias' }
try {
    Remove-OwnedTransientRoot $stagingRoot $parent $output.Name 'staging' -Keep | Out-Null
    throw 'descendant alias was admitted'
} catch {
    if ($_.Exception.Message -notmatch 'fixture descendant alias') { throw }
} finally { Set-Item Function:Assert-NoDescendantPathAlias $originalDescendants }
Assert-Equal $script:removeCalls.Count 1 'descendant delete calls'
$passes.Add('descendant-alias-guard-before-retention')

$script:retainedQualifyingContainer = $false
$script:retainedQualifyingContainerName = $null
$publicationOccurred = $false
$published = $false
$KeepTransientDirectories = $true
$catchSource = $main[0].CatchClauses[0].Extent.Text
$catchDriver = [scriptblock]::Create("try { throw 'original-fixture-error' } $catchSource")
try {
    & $catchDriver | Out-Null
    throw 'source catch did not rethrow'
} catch {
    if ($_.Exception.Message -notmatch 'original-fixture-error') { throw }
}
Assert-Retained $workRoot
Assert-Retained $stagingRoot
Assert-Equal $script:removeCalls.Count 1 'failure keep delete calls'
$passes.Add('failure-retains-original-error-and-roots')

$script:uncertaintyCalls = 0
function Test-B4ContainerBindSourcesMustRemain { return $true }
function Write-B4ContainerUncertainty {
    param([string]$Reason)
    if ($Reason -cne 'runner-exited-before-removal-confirmed') { throw 'wrong uncertainty reason' }
    $script:uncertaintyCalls++
}
try {
    & $catchDriver | Out-Null
    throw 'uncertain-container catch did not rethrow'
} catch {
    if ($_.Exception.Message -notmatch 'original-fixture-error') { throw }
}
Assert-Equal $script:uncertaintyCalls 1 'uncertainty receipt count'
Assert-Retained $workRoot
Assert-Retained $stagingRoot
Assert-Equal $script:removeCalls.Count 1 'uncertain-container delete calls'
$passes.Add('uncertain-container-retains-sources-and-original-error')

$published = $true
$lockStream = $null
$lockOwned = $false
$finallySource = $main[0].Finally.Extent.Text
$successDriver = [scriptblock]::Create("try { } finally $finallySource")
$successMessages = @(& $successDriver)
Assert-Equal $successMessages.Count 1 'success retention message count'
Assert-Equal $successMessages[0] "B4 build: work transient directory retained at $([System.IO.Path]::GetFullPath($workRoot))" 'success retention message'
Assert-Retained $workRoot
Assert-Equal $script:removeCalls.Count 1 'success keep delete calls'
$passes.Add('success-finally-retains-work')

$forwarding = '-Keep:$KeepTransientDirectories'
if ($finallySource.Split(@($forwarding), [System.StringSplitOptions]::None).Count -ne 2) {
    throw 'expected one keep forwarding in exact finally source'
}
$mutantSource = $finallySource.Replace($forwarding, '')
$mutantDriver = [scriptblock]::Create("try { } finally $mutantSource")
$mutantMessages = @(& $mutantDriver)
Assert-Equal $mutantMessages.Count 0 'mutant retention message count'
Assert-Equal $script:removeCalls.Count 2 'mutant must invoke mocked legacy deletion'
Assert-Retained $workRoot
$passes.Add('finally-keep-forwarding-mutant-detected')

$lines = @($passes | ForEach-Object { "PASS $_" }) + "TOTAL $($passes.Count)"
$result = Join-Path $root 'test-result.txt'
$bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
$stream = [System.IO.File]::Open($result, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
$lines
