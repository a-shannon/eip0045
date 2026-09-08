[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('preflight', 'build', 'test', 'clippy', 'verify-invariants', 'preflight-proof-output', 'manifest-proof-output', 'guard-candidate')]
    [string]$Action = 'test',

    [ValidateScript({
        [string]::IsNullOrEmpty($_) -or $_ -match '^[a-z0-9][a-z0-9-]{0,31}$'
    })]
    [string]$Lane = $env:EIP0045_TARGET_LANE,

    [ValidateRange(-1, 1048576)]
    [int]$MinimumFreeGiB = -1,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments = @()
)

function Test-PathOverlap([string]$First, [string]$Second) {
    $firstFull = [System.IO.Path]::GetFullPath($First).TrimEnd('\')
    $secondFull = [System.IO.Path]::GetFullPath($Second).TrimEnd('\')
    if ($firstFull.Equals($secondFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $firstPrefix = $firstFull + '\'
    $secondPrefix = $secondFull + '\'
    return $firstFull.StartsWith($secondPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $secondFull.StartsWith($firstPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-NormalizedFullPath([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $volumeRoot = [System.IO.Path]::GetPathRoot($full)
    if ($full.Equals($volumeRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full
    }
    return $full.TrimEnd('\')
}

function Find-SynchronizedWorkspaceRoot([string]$RepositoryRoot) {
    $current = Get-Item -Force -LiteralPath $RepositoryRoot
    while ($null -ne $current) {
        if ((Test-Path -LiteralPath (Join-Path $current.FullName 'AGENTS.md') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $current.FullName '.agent') -PathType Container)) {
            return $current.FullName
        }
        $current = $current.Parent
    }
    return $RepositoryRoot
}

function Assert-NoReparsePointAncestor([string]$Path, [string]$Label) {
    $current = [System.IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $current)) {
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) {
            throw "$Label has no existing filesystem ancestor: $Path"
        }
        $current = $parent.FullName
    }
    while ($true) {
        $item = Get-Item -Force -LiteralPath $current
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label traverses a symlink, junction, or mount-point alias: $current"
        }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) {
            break
        }
        $current = $parent.FullName
    }
}

if (-not ('Eip0045RunNativePath' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Eip0045RunNativePath
{
    private const uint FileReadAttributes = 0x0080;
    private const uint FileShareRead = 0x0001;
    private const uint FileShareWrite = 0x0002;
    private const uint FileShareDelete = 0x0004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags);

    public static string ResolveDirectory(string path)
    {
        using (SafeFileHandle handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "cannot retain directory for physical path resolution");
            }
            int capacity = 512;
            while (capacity <= 32768)
            {
                StringBuilder buffer = new StringBuilder(capacity);
                uint length = GetFinalPathNameByHandle(
                    handle,
                    buffer,
                    (uint)buffer.Capacity,
                    0);
                if (length == 0)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "cannot resolve retained directory identity");
                }
                if (length < buffer.Capacity)
                {
                    string resolved = buffer.ToString();
                    if (resolved.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                    {
                        return @"\\" + resolved.Substring(8);
                    }
                    if (resolved.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                    {
                        string dosPath = resolved.Substring(4);
                        if (dosPath.Length >= 3 &&
                            Char.IsLetter(dosPath[0]) &&
                            dosPath[1] == ':' &&
                            dosPath[2] == '\\')
                        {
                            return dosPath;
                        }
                        throw new InvalidOperationException(
                            "resolved directory has no DOS or UNC path identity");
                    }
                    return resolved;
                }
                capacity = checked((int)length + 1);
            }
            throw new InvalidOperationException("resolved directory path exceeds 32768 characters");
        }
    }
}
'@
}

function Resolve-PhysicalProspectivePath([string]$Path, [string]$Label) {
    $probe = [System.IO.Path]::GetFullPath($Path)
    $suffix = [System.Collections.Generic.List[string]]::new()
    while (-not (Test-Path -LiteralPath $probe)) {
        $component = [System.IO.Path]::GetFileName($probe)
        $parent = [System.IO.Directory]::GetParent($probe)
        if ([string]::IsNullOrEmpty($component) -or $null -eq $parent) {
            throw "$Label has no resolvable existing ancestor: $Path"
        }
        $suffix.Insert(0, $component)
        $probe = $parent.FullName
    }
    $item = Get-Item -Force -LiteralPath $probe
    if (-not $item.PSIsContainer) {
        throw "$Label has a non-directory existing ancestor: $probe"
    }
    $physical = [Eip0045RunNativePath]::ResolveDirectory($probe)
    foreach ($component in $suffix) {
        $physical = Join-Path $physical $component
    }
    return Get-NormalizedFullPath $physical
}

function Get-ForbiddenSynchronizedRoots([string]$WorkspaceRoot) {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $candidates.Add($WorkspaceRoot)
    foreach ($name in @('OneDrive', 'OneDriveCommercial', 'OneDriveConsumer')) {
        $value = [System.Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $candidates.Add($value)
        }
    }
    $providerRoot = 'HKCU:\Software\SyncEngines\Providers\OneDrive'
    if (Test-Path -LiteralPath $providerRoot) {
        $providerKeys = @((Get-Item -LiteralPath $providerRoot)) + @(
            Get-ChildItem -LiteralPath $providerRoot -Recurse -ErrorAction Stop
        )
        foreach ($key in $providerKeys) {
            $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ($properties.PSObject.Properties.Name -contains 'MountPoint' -and
                -not [string]::IsNullOrWhiteSpace($properties.MountPoint)) {
                $candidates.Add([string]$properties.MountPoint)
            }
        }
    }

    $explicitRoots = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:EIP0045_FORBIDDEN_SYNC_ROOTS)) {
        foreach ($value in $env:EIP0045_FORBIDDEN_SYNC_ROOTS.Split([System.IO.Path]::PathSeparator)) {
            if ([string]::IsNullOrWhiteSpace($value)) {
                throw 'EIP0045_FORBIDDEN_SYNC_ROOTS contains an empty path'
            }
            $explicitRoots.Add($value)
            $candidates.Add($value)
        }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in $candidates) {
        if ($candidate.Contains("`r") -or $candidate.Contains("`n")) {
            throw 'a synchronized-root path contains CR or LF'
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
            if ($explicitRoots.Contains($candidate) -or
                $candidate.Equals($WorkspaceRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "configured synchronized root is unavailable: $candidate"
            }
            continue
        }
        $physical = Resolve-PhysicalProspectivePath $candidate 'synchronized root'
        if ($seen.Add($physical)) {
            $roots.Add($physical)
        }
    }
    return $roots.ToArray()
}

if (-not [string]::IsNullOrEmpty($Lane) -and $Lane -notmatch '^[a-z0-9][a-z0-9-]{0,31}$') {
    throw 'EIP0045_TARGET_LANE must be empty or match ^[a-z0-9][a-z0-9-]{0,31}$'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workspaceRoot = Find-SynchronizedWorkspaceRoot $repoRoot
$forbiddenSyncRoots = @(Get-ForbiddenSynchronizedRoots $workspaceRoot)
$targetRoot = if ($env:EIP0045_TARGET_DIR) {
    $env:EIP0045_TARGET_DIR
} else {
    Join-Path $env:LOCALAPPDATA 'eip-0045-profile\target'
}
$eip0045Target = if ([string]::IsNullOrEmpty($Lane)) {
    $targetRoot
} else {
    Join-Path $targetRoot $Lane
}
$eip0045Target = Get-NormalizedFullPath $eip0045Target

if (Test-PathOverlap $eip0045Target $workspaceRoot) {
    throw "EIP-0045 target directory overlaps the synchronized repository or workspace: $eip0045Target"
}
Assert-NoReparsePointAncestor $eip0045Target 'EIP-0045 target directory'
$eip0045Target = Resolve-PhysicalProspectivePath $eip0045Target 'EIP-0045 target directory'
foreach ($forbiddenRoot in $forbiddenSyncRoots) {
    if (Test-PathOverlap $eip0045Target $forbiddenRoot) {
        throw "EIP-0045 target directory overlaps the synchronized repository or workspace: $eip0045Target"
    }
}
if ($env:CARGO_HOME -and (Test-PathOverlap $env:CARGO_HOME $workspaceRoot)) {
    throw "EIP-0045 CARGO_HOME overlaps the synchronized repository or workspace: $env:CARGO_HOME"
}
if ($env:CARGO_HOME) {
    Assert-NoReparsePointAncestor $env:CARGO_HOME 'EIP-0045 CARGO_HOME'
    $physicalCargoHome = Resolve-PhysicalProspectivePath $env:CARGO_HOME 'EIP-0045 CARGO_HOME'
    foreach ($forbiddenRoot in $forbiddenSyncRoots) {
        if (Test-PathOverlap $physicalCargoHome $forbiddenRoot) {
            throw "EIP-0045 CARGO_HOME overlaps the synchronized repository or workspace: $physicalCargoHome"
        }
    }
    $env:CARGO_HOME = $physicalCargoHome
}

New-Item -ItemType Directory -Path $eip0045Target -Force | Out-Null
$minimum = if ($MinimumFreeGiB -ge 0) {
    [int64]$MinimumFreeGiB
} elseif ($env:EIP0045_MIN_FREE_GIB) {
    if ($env:EIP0045_MIN_FREE_GIB -notmatch '^[0-9]+$') {
        throw 'EIP0045_MIN_FREE_GIB must be a non-negative integer no greater than 1048576'
    }
    try {
        [int64]::Parse($env:EIP0045_MIN_FREE_GIB, [Globalization.CultureInfo]::InvariantCulture)
    } catch {
        throw 'EIP0045_MIN_FREE_GIB must be a non-negative integer no greater than 1048576'
    }
} else {
    [int64]5
}
if ($minimum -lt 0 -or $minimum -gt 1048576) {
    throw 'EIP0045_MIN_FREE_GIB must be a non-negative integer no greater than 1048576'
}
$targetVolume = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($eip0045Target))
$minimumBytes = $minimum * [int64]1GB
if ($targetVolume.AvailableFreeSpace -lt $minimumBytes) {
    throw "EIP-0045 target free space is below the configured minimum: $($targetVolume.AvailableFreeSpace) < $minimumBytes bytes"
}

$env:CARGO_TARGET_DIR = $eip0045Target
$laneLabel = if ([string]::IsNullOrEmpty($Lane)) { 'shared' } else { $Lane }
$lockPath = Join-Path $eip0045Target '.eip0045-run.lock'
$lockStream = $null
$locationPushed = $false
try {
    try {
        $lockStream = [System.IO.File]::Open(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    } catch [System.IO.IOException] {
        throw "EIP-0045 target lane is already in use; select a distinct -Lane or EIP0045_TARGET_DIR: $laneLabel"
    }
    $lockBytes = [System.Text.Encoding]::UTF8.GetBytes("pid=$PID`nlane=$laneLabel`n")
    $lockStream.SetLength(0)
    $lockStream.Write($lockBytes, 0, $lockBytes.Length)
    $lockStream.Flush()

    Push-Location -LiteralPath $repoRoot
    $locationPushed = $true
    if ($Action -eq 'preflight') {
        Write-Output 'schema=eip0045-local-run-preflight-v1'
        Write-Output "lane=$laneLabel"
        Write-Output "targetDir=$eip0045Target"
        Write-Output "availableFreeBytes=$($targetVolume.AvailableFreeSpace)"
        Write-Output "minimumFreeBytes=$minimumBytes"
        return
    }

    switch ($Action) {
        'build' {
            & cargo +1.89.0 build --workspace --locked @Arguments
        }
        'test' {
            & cargo +1.89.0 test --workspace --locked @Arguments
        }
        'clippy' {
            & cargo +1.89.0 clippy --workspace --all-targets --locked -- -D warnings
        }
        'verify-invariants' {
            & cargo +1.89.0 run -p eip-0045-reproduction --locked -- verify-invariants @Arguments
        }
        'preflight-proof-output' {
            & cargo +1.89.0 run -p eip-0045-reproduction --locked -- preflight-proof-output @Arguments
        }
        'manifest-proof-output' {
            & cargo +1.89.0 run -p eip-0045-reproduction --locked -- manifest-proof-output @Arguments
        }
        'guard-candidate' {
            & cargo +1.89.0 run -p eip-0045-reproduction --locked -- guard-candidate --repo-root $repoRoot @Arguments
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "EIP-0045 reproduction command failed with exit code $LASTEXITCODE"
    }
} finally {
    if ($locationPushed) {
        Pop-Location
    }
    if ($null -ne $lockStream) {
        $lockStream.Dispose()
        Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
    }
}
