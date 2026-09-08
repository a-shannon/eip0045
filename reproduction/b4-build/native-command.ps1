function Invoke-B4NativeCapture {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [switch]$Discard
    )

    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 turns redirected native stderr into ErrorRecord
        # objects. Keep only this native invocation non-terminating, then decide
        # from its exact process exit status.
        $ErrorActionPreference = 'Continue'
        if ($Discard) {
            & $FilePath @Arguments *> $null
            $output = @()
        } else {
            $output = @(& $FilePath @Arguments 2>&1 | ForEach-Object { "$_" })
        }
        $exitStatus = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }

    return [pscustomobject]@{
        ExitStatus = [int]$exitStatus
        Output = [string[]]$output
    }
}

function Invoke-B4NativePassthrough {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory)]
        [ref]$ExitStatus
    )

    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $FilePath @Arguments
        $ExitStatus.Value = [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
}

function Get-B4WindowsHardLinkCount([string]$Path) {
    if ($null -eq ('Eip0045B4.NativeFileIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Eip0045B4
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    public static class NativeFileIdentity
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out ByHandleFileInformation information
        );

        public static uint HardLinkCount(string path)
        {
            using (FileStream stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete
            ))
            {
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(stream.SafeFileHandle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return information.NumberOfLinks;
            }
        }
    }
}
'@ | Out-Null
    }
    return [uint32][Eip0045B4.NativeFileIdentity]::HardLinkCount($Path)
}

function Assert-B4PlainSingleLinkFile([string]$Path, [string]$Label) {
    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label is not a plain file: $Path"
    }
    $links = Get-B4WindowsHardLinkCount $item.FullName
    if ($links -ne 1) { throw "$Label must have exactly one hard link: $Path (observed $links)" }
}

function Assert-B4NoDescendantHardLink([string]$Root, [string]$Label) {
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in Get-ChildItem -Force -LiteralPath $directory) {
            if ($item.PSIsContainer) {
                $pending.Push($item.FullName)
            } else {
                Assert-B4PlainSingleLinkFile $item.FullName "$Label descendant"
            }
        }
    }
}

function Assert-B4NoGitEnvironmentOverride {
    foreach ($name in @(
        'GIT_DIR',
        'GIT_WORK_TREE',
        'GIT_COMMON_DIR',
        'GIT_OBJECT_DIRECTORY',
        'GIT_ALTERNATE_OBJECT_DIRECTORIES',
        'GIT_INDEX_FILE'
    )) {
        if (Test-Path -LiteralPath "Env:$name") {
            throw "B4 Git checkout validation forbids inherited $name"
        }
    }
}

function Invoke-B4GitSingleLine([string]$Repo, [string[]]$Arguments, [string]$Label) {
    $result = Invoke-B4NativeCapture -FilePath 'git' -Arguments (@('-C', $Repo) + $Arguments)
    if ($result.ExitStatus -ne 0 -or $result.Output.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace($result.Output[0])) {
        throw "cannot derive $Label for standalone B4 checkout: $Repo"
    }
    return $result.Output[0].Trim()
}

function Assert-B4StandaloneGitCheckout([string]$Repo) {
    Assert-B4NoGitEnvironmentOverride
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw 'git is required to validate standalone B4 checkouts'
    }

    $repoItem = Get-Item -Force -LiteralPath $Repo -ErrorAction Stop
    if (-not $repoItem.PSIsContainer -or
        (($repoItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "B4 repository root is not a plain directory: $Repo"
    }
    $canonicalRepo = [System.IO.Path]::GetFullPath($repoItem.FullName).TrimEnd('\')
    $gitPath = Join-Path $canonicalRepo '.git'
    $gitItem = Get-Item -Force -LiteralPath $gitPath -ErrorAction Stop
    if (-not $gitItem.PSIsContainer -or
        (($gitItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "B4 requires a standalone .git directory, not a worktree or alias: $gitPath"
    }
    $canonicalGit = [System.IO.Path]::GetFullPath($gitItem.FullName).TrimEnd('\')

    $topLevel = Invoke-B4GitSingleLine $canonicalRepo @('rev-parse', '--show-toplevel') 'Git work-tree root'
    $absoluteGit = Invoke-B4GitSingleLine $canonicalRepo @('rev-parse', '--absolute-git-dir') 'Git administration root'
    $commonGit = Invoke-B4GitSingleLine $canonicalRepo @('rev-parse', '--path-format=absolute', '--git-common-dir') 'Git common root'
    $objects = Invoke-B4GitSingleLine $canonicalRepo @('rev-parse', '--path-format=absolute', '--git-path', 'objects') 'Git object root'

    foreach ($pair in @(
        [pscustomobject]@{ Actual = $topLevel; Expected = $canonicalRepo; Label = 'work-tree root' },
        [pscustomobject]@{ Actual = $absoluteGit; Expected = $canonicalGit; Label = 'administration root' },
        [pscustomobject]@{ Actual = $commonGit; Expected = $canonicalGit; Label = 'common root' },
        [pscustomobject]@{ Actual = $objects; Expected = (Join-Path $canonicalGit 'objects'); Label = 'object root' }
    )) {
        $actual = [System.IO.Path]::GetFullPath($pair.Actual).TrimEnd('\')
        $expected = [System.IO.Path]::GetFullPath($pair.Expected).TrimEnd('\')
        if (-not $actual.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "B4 checkout $($pair.Label) is not private to the checkout: $actual"
        }
    }

    foreach ($name in @('alternates', 'http-alternates')) {
        $candidate = Join-Path $canonicalGit "objects\info\$name"
        if (Test-Path -LiteralPath $candidate) {
            throw "B4 checkout contains forbidden Git object alternates metadata: $candidate"
        }
    }
}

function Initialize-B4ContainerGuard {
    $existing = Get-Variable -Scope Script -Name B4ContainerGuardState -ErrorAction SilentlyContinue
    if ($null -ne $existing -and $existing.Value -notin @('idle', 'removed')) {
        throw "B4 container guard cannot be reset from state $($existing.Value)"
    }
    $script:B4ContainerGuardState = 'idle'
    $script:B4ContainerGuardName = $null
    $script:B4ContainerGuardDiagnosticRoot = $null
    $script:B4ContainerBindSourcesMustRemain = $false
}

function Start-B4ContainerGuard([string]$Name, [string]$DiagnosticRoot) {
    if ($script:B4ContainerGuardState -notin @('idle', 'removed')) {
        throw "B4 container guard cannot start from state $($script:B4ContainerGuardState)"
    }
    if ($Name -notmatch '^[a-z0-9-]+$') { throw 'invalid B4 qualifying-container name' }
    $root = Get-Item -Force -LiteralPath $DiagnosticRoot -ErrorAction Stop
    if (-not $root.PSIsContainer -or
        (($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'B4 qualifying-container diagnostic root is not a plain directory'
    }
    $script:B4ContainerGuardState = 'possible'
    $script:B4ContainerGuardName = $Name
    $script:B4ContainerGuardDiagnosticRoot = $root.FullName
    $script:B4ContainerBindSourcesMustRemain = $true
}

function Set-B4ContainerInspected([string]$Name) {
    if ($script:B4ContainerGuardState -ne 'possible' -or
        $script:B4ContainerGuardName -cne $Name) {
        throw 'B4 inspected-container transition does not match the active guard'
    }
    $script:B4ContainerGuardState = 'observed'
}

function Complete-B4ContainerRemoval([string]$Name) {
    if ($script:B4ContainerGuardState -ne 'observed' -or
        $script:B4ContainerGuardName -cne $Name) {
        throw 'B4 removed-container transition does not match an inspected container'
    }
    $script:B4ContainerGuardState = 'removed'
    $script:B4ContainerBindSourcesMustRemain = $false
}

function Test-B4ContainerBindSourcesMustRemain {
    return [bool]$script:B4ContainerBindSourcesMustRemain
}

function Write-B4ContainerUncertainty([string]$Reason) {
    if (-not (Test-B4ContainerBindSourcesMustRemain)) { return }
    if ($Reason -notmatch '^[a-z0-9-]+$') { throw 'invalid B4 container uncertainty reason' }
    if ($script:B4ContainerGuardState -notin @('possible', 'observed')) {
        throw 'B4 container uncertainty cannot be recorded from the current guard state'
    }

    $final = Join-Path $script:B4ContainerGuardDiagnosticRoot 'container-presence-uncertain.txt'
    if (Test-Path -LiteralPath $final) {
        Assert-B4PlainSingleLinkFile $final 'B4 container uncertainty path'
        return
    }

    $temporary = Join-Path $script:B4ContainerGuardDiagnosticRoot (
        '.container-presence-uncertain.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    )
    $content = @(
        'schema=eip0045-b4-host-container-presence-v1',
        "containerName=$($script:B4ContainerGuardName)",
        "state=$($script:B4ContainerGuardState)",
        "reason=$Reason",
        'bindSourcesPreserved=true',
        'removalConfirmed=false'
    ) -join "`n"
    try {
        [System.IO.File]::WriteAllText(
            $temporary,
            $content + "`n",
            [System.Text.UTF8Encoding]::new($false)
        )
        try {
            [System.IO.File]::Move($temporary, $final)
        } catch {
            if (-not (Test-Path -LiteralPath $final -PathType Leaf)) { throw }
            Assert-B4PlainSingleLinkFile $final 'B4 container uncertainty path'
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}
