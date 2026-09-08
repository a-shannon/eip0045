[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SeedRoot,

    [Parameter(Mandatory)]
    [string]$OutputRoot,

    [Parameter(Mandatory)]
    [string]$SecondSeedRoot,

    [Parameter(Mandatory)]
    [string]$SecondRepoRoot,

    [Parameter(Mandatory)]
    [string]$RuntimeImage
)

$ErrorActionPreference = 'Stop'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Fail([string]$Message) { throw "B4 build: $Message" }
$nativeCommandHelper = Join-Path $PSScriptRoot 'b4-build\native-command.ps1'
if (-not (Test-Path -LiteralPath $nativeCommandHelper -PathType Leaf)) {
    Fail "native-command helper is absent: $nativeCommandHelper"
}
. $nativeCommandHelper

function Write-LfUtf8([string]$Path, [string[]]$Lines) {
    $content = if ($Lines.Count -eq 0) { '' } else { ($Lines -join "`n") + "`n" }
    [System.IO.File]::WriteAllText($Path, $content, [System.Text.UTF8Encoding]::new($false))
}
function Reject-MountUnsafeValue([string]$Value, [string]$Label) {
    if ($Value.Contains("`r") -or $Value.Contains("`n")) { Fail "$Label contains CR or LF" }
    if ($Value.Contains(',')) { Fail "$Label contains a comma, which is unsafe in Docker --mount syntax" }
}
function Require-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { Fail "missing directory: $Path" }
}
function Test-PathAlias([System.IO.FileSystemInfo]$Item) {
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { return $false }
    return $true
}
function Assert-NoPathAliasAncestor([string]$Path, [string]$Label) {
    $current = [System.IO.Path]::GetFullPath($Path)
    while ($true) {
        $item = Get-Item -Force -LiteralPath $current
        if (Test-PathAlias $item) { Fail "$Label traverses a symlink or junction: $current" }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}
function Assert-NoDescendantPathAlias([string]$Root, [string]$Label) {
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in Get-ChildItem -Force -LiteralPath $directory) {
            if (Test-PathAlias $item) {
                Fail "$Label contains a symlink, junction, or mount-point alias: $($item.FullName)"
            }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}
function Resolve-CheckedDirectory([string]$Path, [string]$Label) {
    Reject-MountUnsafeValue $Path $Label
    Require-Directory $Path
    $item = Get-Item -Force -LiteralPath $Path
    if (Test-PathAlias $item) { Fail "$Label must not be a symlink or junction: $Path" }
    $resolved = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
    $volumeRoot = [System.IO.Path]::GetPathRoot($resolved)
    if (-not $resolved.Equals($volumeRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        $resolved = $resolved.TrimEnd('\')
    }
    Assert-NoPathAliasAncestor $resolved $Label
    Reject-MountUnsafeValue $resolved $Label
    return $resolved
}
function Resolve-ProspectiveOutput([string]$Path) {
    Reject-MountUnsafeValue $Path 'output path'
    $full = [System.IO.Path]::GetFullPath($Path)
    $name = [System.IO.Path]::GetFileName($full)
    if ([string]::IsNullOrWhiteSpace($name) -or $name -eq '.' -or $name -eq '..') {
        Fail 'output path must name a new directory below an existing parent'
    }
    $parentInfo = [System.IO.Directory]::GetParent($full)
    if ($null -eq $parentInfo) { Fail 'output path must have an existing parent directory' }
    $parent = Resolve-CheckedDirectory $parentInfo.FullName 'output parent'
    $prospective = Join-Path $parent $name
    Reject-MountUnsafeValue $prospective 'output path'
    if (Test-Path -LiteralPath $prospective) { Fail 'final output directory must not already exist' }
    return [pscustomobject]@{ Parent = $parent; Name = $name; Path = $prospective }
}
function Test-PathWithin([string]$Child, [string]$Parent) {
    if ($Child.Equals($Parent, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    $prefix = $Parent.TrimEnd('\') + '\'
    return $Child.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}
function Assert-Disjoint([string]$First, [string]$FirstLabel, [string]$Second, [string]$SecondLabel) {
    if ((Test-PathWithin $First $Second) -or (Test-PathWithin $Second $First)) {
        Fail "$FirstLabel and $SecondLabel must be path-disjoint: $First ; $Second"
    }
}
function Assert-FileIdentityEqual([string]$First, [string]$Second, [string]$Message) {
    $firstItem = Get-Item -Force -LiteralPath $First
    $secondItem = Get-Item -Force -LiteralPath $Second
    if ($firstItem.PSIsContainer -or $secondItem.PSIsContainer -or
        $firstItem.Length -ne $secondItem.Length -or
        (Get-FileHash -LiteralPath $First -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $Second -Algorithm SHA256).Hash) {
        Fail $Message
    }
}
function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { Fail "docker command failed: $($Arguments -join ' ')" }
}
function Invoke-DockerCapture([string[]]$Arguments) {
    $output = @(& docker @Arguments)
    if ($LASTEXITCODE -ne 0) { Fail "docker command failed: $($Arguments -join ' ')" }
    return ($output -join "`n")
}
function Invoke-QualifyingContainer(
    [string]$Name,
    [string[]]$RunArguments,
    [string]$DiagnosticRoot
) {
    if (Test-Path -LiteralPath $DiagnosticRoot) { Fail "host diagnostic root already exists: $DiagnosticRoot" }
    New-Item -ItemType Directory -Path $DiagnosticRoot | Out-Null
    $namePreflight = Invoke-B4NativeCapture -FilePath 'docker' -Arguments @('container', 'inspect', $Name) -Discard
    if ($namePreflight.ExitStatus -eq 0) { Fail "qualifying container name is already occupied: $Name" }

    $runStatus = 0
    $dockerRunArguments = @('run', '--name', $Name) + $RunArguments
    Start-B4ContainerGuard -Name $Name -DiagnosticRoot $DiagnosticRoot
    Invoke-B4NativePassthrough -FilePath 'docker' -Arguments $dockerRunArguments -ExitStatus ([ref]$runStatus)
    Write-LfUtf8 (Join-Path $DiagnosticRoot 'run-status.txt') @(
        'schema=eip0045-b4-host-container-run-v1',
        "containerName=$Name",
        "exitStatus=$runStatus"
    )

    $inspectResult = Invoke-B4NativeCapture -FilePath 'docker' -Arguments @('container', 'inspect', $Name)
    $inspectOutput = $inspectResult.Output
    $inspectStatus = $inspectResult.ExitStatus
    if ($inspectStatus -eq 0) {
        Set-B4ContainerInspected -Name $Name
        Write-LfUtf8 (Join-Path $DiagnosticRoot 'container-inspect.json') $inspectOutput
    } else {
        Write-B4ContainerUncertainty -Reason 'post-run-inspection-failed'
        Write-LfUtf8 (Join-Path $DiagnosticRoot 'container-inspect-error.txt') $inspectOutput
    }
    $logResult = Invoke-B4NativeCapture -FilePath 'docker' -Arguments @('logs', '--timestamps', $Name)
    $logOutput = $logResult.Output
    $logStatus = $logResult.ExitStatus
    if ($logStatus -eq 0) {
        Write-LfUtf8 (Join-Path $DiagnosticRoot 'container-logs.txt') $logOutput
    } else {
        Write-LfUtf8 (Join-Path $DiagnosticRoot 'container-logs-error.txt') $logOutput
    }

    if ($runStatus -ne 0) {
        if ($inspectStatus -eq 0) {
            $script:retainedQualifyingContainer = $true
            $script:retainedQualifyingContainerName = $Name
            Fail "qualifying container $Name failed with status $runStatus and was retained for diagnosis"
        }
        Fail "docker run failed with status $runStatus and container presence could not be confirmed; original bind sources were preserved"
    }
    if ($inspectStatus -ne 0 -or $logStatus -ne 0) {
        if ($inspectStatus -eq 0) {
            $script:retainedQualifyingContainer = $true
            $script:retainedQualifyingContainerName = $Name
        }
        Fail "successful qualifying container $Name could not be fully diagnosed; original bind sources were preserved"
    }
    $removeResult = Invoke-B4NativeCapture -FilePath 'docker' -Arguments @('rm', $Name) -Discard
    if ($removeResult.ExitStatus -ne 0) {
        $script:retainedQualifyingContainer = $true
        $script:retainedQualifyingContainerName = $Name
        Write-B4ContainerUncertainty -Reason 'removal-not-confirmed'
        Fail "successful qualifying container $Name could not be removed and was retained for diagnosis"
    }
    Complete-B4ContainerRemoval -Name $Name
}
function Assert-ExactLocalImage([string]$Reference) {
    Invoke-Docker @('image', 'inspect', $Reference) | Out-Null
    $identity = Invoke-DockerCapture @('image', 'inspect', $Reference, '--format', '{{.Os}}/{{.Architecture}} {{json .RepoDigests}}')
    if ($identity -notmatch 'linux/amd64' -or $identity -notlike "*$($Reference.Split('@')[1])*") {
        Fail "local image identity/platform mismatch: $Reference"
    }
}
function Write-BaseImageEvidence([string]$GuestReference, [string]$HostReference, [string]$Path) {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($image in @(@('guestBuilder', $GuestReference), @('hostRust', $HostReference))) {
        $label = $image[0]
        $reference = $image[1]
        $lines.Add("$label.reference=$reference")
        $lines.Add("$label.platform=$(Invoke-DockerCapture @('image', 'inspect', $reference, '--format', '{{.Os}}/{{.Architecture}}'))")
        $lines.Add("$label.id=$(Invoke-DockerCapture @('image', 'inspect', $reference, '--format', '{{.Id}}'))")
        $lines.Add("$label.created=$(Invoke-DockerCapture @('image', 'inspect', $reference, '--format', '{{.Created}}'))")
        $lines.Add("$label.descriptor=$(Invoke-DockerCapture @('image', 'inspect', $reference, '--format', '{{json .Descriptor}}'))")
        $lines.Add("$label.config=$(Invoke-DockerCapture @('image', 'inspect', $reference, '--format', '{{json .Config}}'))")
        $lines.Add("$label.rootfs=$(Invoke-DockerCapture @('image', 'inspect', $reference, '--format', '{{json .RootFS}}'))")
    }
    Write-LfUtf8 $Path $lines.ToArray()
}
function Assert-LocalRuntimeImage([string]$Reference) {
    $expectedManifest = 'sha256:1aa2ca80b59886af9ab34cf9775a567a80aacb03c0c29176c9120e1f34fcd855'
    $expectedConfig = 'sha256:e89c6b7bdb6d5dbf7456f550fd17e8983edba597881a9a8e806b1bc589ac3074'
    Invoke-Docker @('image', 'inspect', $Reference) | Out-Null
    $attestation = Invoke-DockerCapture @('image', 'inspect', $Reference, '--format', '{{.Os}}/{{.Architecture}}')
    $descriptor = Invoke-DockerCapture @('image', 'inspect', $Reference, '--format', '{{json .Descriptor}}')
    if ($attestation -notmatch 'linux/amd64' -or $descriptor -notlike "*$expectedManifest*" -or $descriptor -notlike "*$expectedConfig*") { Fail 'runtime manifest/config/platform mismatch' }
    $created = Invoke-DockerCapture @('image', 'inspect', $Reference, '--format', '{{.Created}}')
    if ($created -cne '2026-02-03T00:19:36Z') { Fail 'runtime image Created timestamp mismatch' }
    Invoke-Docker @('image', 'inspect', $expectedManifest) | Out-Null
    $immutableDescriptor = Invoke-DockerCapture @('image', 'inspect', $expectedManifest, '--format', '{{json .Descriptor}}')
    if ($immutableDescriptor -notlike "*$expectedManifest*" -or $immutableDescriptor -notlike "*$expectedConfig*") { Fail 'immutable runtime descriptor changed' }
    return $expectedManifest
}
function Write-RuntimeEvidence([string]$RequestedReference, [string]$ExecutedReference, [string]$Path) {
    Write-LfUtf8 $Path @(
        "requestedReference=$RequestedReference",
        "executedReference=$ExecutedReference",
        "platform=$(Invoke-DockerCapture @('image', 'inspect', $ExecutedReference, '--format', '{{.Os}}/{{.Architecture}}'))",
        "id=$(Invoke-DockerCapture @('image', 'inspect', $ExecutedReference, '--format', '{{.Id}}'))",
        "created=$(Invoke-DockerCapture @('image', 'inspect', $ExecutedReference, '--format', '{{.Created}}'))",
        "descriptor=$(Invoke-DockerCapture @('image', 'inspect', $ExecutedReference, '--format', '{{json .Descriptor}}'))",
        "config=$(Invoke-DockerCapture @('image', 'inspect', $ExecutedReference, '--format', '{{json .Config}}'))",
        "rootfs=$(Invoke-DockerCapture @('image', 'inspect', $ExecutedReference, '--format', '{{json .RootFS}}'))"
    )
}
function Get-GitEvidenceLines([string]$Repo) {
    try {
        Assert-B4StandaloneGitCheckout $Repo
    } catch {
        Fail "B4 requires a standalone clean Git checkout with a private object store: $($_.Exception.Message)"
    }
    $head = (& git -C $Repo rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { Fail "cannot read workspace Git HEAD: $Repo" }
    $tree = (& git -C $Repo rev-parse 'HEAD^{tree}').Trim()
    if ($LASTEXITCODE -ne 0) { Fail "cannot read workspace Git tree: $Repo" }
    $status = @(& git -C $Repo status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) { Fail "cannot read workspace Git status: $Repo" }
    if ($status.Count -ne 0) { Fail "B4 requires a clean workspace Git tree: $Repo" }
    return @("head=$head", "tree=$tree", 'storage=standalone-private-object-store', 'statusBegin', 'statusEnd')
}
function Write-GitEvidence([string]$Repo, [string]$Path) {
    Write-LfUtf8 $Path (Get-GitEvidenceLines $Repo)
}
function Get-TreeManifestLines([string]$EvidenceRoot) {
    $relativePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $EvidenceRoot -Recurse -Force -File) {
        $relative = $file.FullName.Substring($EvidenceRoot.Length + 1).Replace('\', '/')
        if ($relative.Contains("`r") -or $relative.Contains("`n")) { Fail 'generated evidence contains a path with CR or LF' }
        $relativePaths.Add($relative)
    }
    $relativePaths.Sort([System.StringComparer]::Ordinal)
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in $relativePaths) {
        $path = Join-Path $EvidenceRoot $relative.Replace('/', '\')
        $item = Get-Item -Force -LiteralPath $path
        $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines.Add("file path=$relative sha256=$digest size=$($item.Length)")
    }
    return $lines.ToArray()
}
function Write-EvidenceManifest([string]$EvidenceRoot) {
    Write-LfUtf8 (Join-Path $EvidenceRoot 'evidence-manifest.txt') (Get-TreeManifestLines $EvidenceRoot)
}
function Remove-OwnedTransientRoot([string]$Path, [string]$Parent, [string]$OutputName, [string]$Kind) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $actualParent = [System.IO.Directory]::GetParent($full).FullName
    if ($Kind -ne 'work' -and $Kind -ne 'staging') { Fail "unknown transient directory kind: $Kind" }
    $expectedPrefix = ".$OutputName.b4-$Kind."
    if (-not $actualParent.Equals($Parent, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [System.IO.Path]::GetFileName($full).StartsWith($expectedPrefix, [System.StringComparison]::Ordinal)) {
        Fail "refusing to clean an unowned transient directory: $full"
    }
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -Force -LiteralPath $full
        if (Test-PathAlias $item) { Fail "refusing to clean aliased transient directory: $full" }
        Assert-NoDescendantPathAlias $full "$Kind transient directory"
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}
function Invoke-B4BuildRun(
    [string]$Label,
    [string]$Repo,
    [string]$SeedCargo,
    [string]$SeedLfs,
    [string]$EvidenceRoot,
    [string]$WorkRoot,
    [string]$RuntimeReference
) {
    $artifact = Join-Path $EvidenceRoot $Label
    $target = Join-Path $WorkRoot "$Label-target"
    $work = Join-Path $WorkRoot "$Label-work"
    $hostDiagnostics = Join-Path $WorkRoot "$Label-host-diagnostics"
    $containerName = "eip0045-b4-$Label-$([Guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $artifact, $target, $work | Out-Null
    Assert-NoDescendantPathAlias $Repo "$Label repository"
    Assert-NoDescendantPathAlias $SeedCargo "$Label Cargo seed"
    Assert-NoDescendantPathAlias $SeedLfs "$Label LFS seed"
    Assert-B4NoDescendantHardLink $Repo "$Label repository"
    Assert-B4NoDescendantHardLink $SeedCargo "$Label Cargo seed"
    Assert-B4NoDescendantHardLink $SeedLfs "$Label LFS seed"
    $gitBefore = Join-Path $artifact 'workspace-git-before.txt'
    $gitAfter = Join-Path $artifact 'workspace-git-after.txt'
    Write-GitEvidence $Repo $gitBefore
    Invoke-QualifyingContainer $containerName @(
        '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '512', '--cpuset-cpus', '0-3', '--memory', '12g', '--memory-swap', '12g',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=1g', '--tmpfs', '/home:rw,nosuid,nodev,noexec,size=2g',
        '--mount', "type=bind,src=$Repo,dst=/workspace,readonly",
        '--mount', "type=bind,src=$SeedCargo,dst=/seed/cargo,readonly",
        '--mount', "type=bind,src=$SeedLfs,dst=/seed/lfs,readonly",
        '--mount', "type=bind,src=$target,dst=/target",
        '--mount', "type=bind,src=$work,dst=/work",
        '--mount', "type=bind,src=$artifact,dst=/output",
        $RuntimeReference, 'bash', '/workspace/reproduction/b4-build/container-build.sh', $Label
    ) $hostDiagnostics
    Write-GitEvidence $Repo $gitAfter
    if ([System.IO.File]::ReadAllText($gitBefore) -cne [System.IO.File]::ReadAllText($gitAfter)) { Fail 'workspace Git state changed during build' }
    [System.IO.File]::Copy($gitBefore, (Join-Path $artifact 'workspace-git.txt'), $false)
}

Reject-MountUnsafeValue $RuntimeImage 'runtime image reference'
$repoRoot = Resolve-CheckedDirectory (Join-Path $PSScriptRoot '..') 'primary repository'
$secondRepoRoot = Resolve-CheckedDirectory $SecondRepoRoot 'secondary repository'
$seedRoot = Resolve-CheckedDirectory $SeedRoot 'primary seed'
$secondSeedRoot = Resolve-CheckedDirectory $SecondSeedRoot 'secondary seed'
$seedCargoRoot = Resolve-CheckedDirectory (Join-Path $seedRoot 'cargo') 'primary Cargo seed'
$seedLfsRoot = Resolve-CheckedDirectory (Join-Path $seedRoot 'lfs') 'primary LFS seed'
$secondSeedCargoRoot = Resolve-CheckedDirectory (Join-Path $secondSeedRoot 'cargo') 'secondary Cargo seed'
$secondSeedLfsRoot = Resolve-CheckedDirectory (Join-Path $secondSeedRoot 'lfs') 'secondary LFS seed'
foreach ($required in @(
    (Join-Path $repoRoot 'profiles\risc0-v3-succinct'),
    (Join-Path $secondRepoRoot 'reproduction'), (Join-Path $secondRepoRoot 'methods'),
    (Join-Path $secondRepoRoot 'generator'), (Join-Path $secondRepoRoot 'profiles\risc0-v3-succinct')
)) { Require-Directory $required }
if (-not (Test-PathWithin $seedCargoRoot $seedRoot) -or -not (Test-PathWithin $seedLfsRoot $seedRoot)) {
    Fail 'primary seed sub-roots must remain below the primary seed root'
}
if (-not (Test-PathWithin $secondSeedCargoRoot $secondSeedRoot) -or -not (Test-PathWithin $secondSeedLfsRoot $secondSeedRoot)) {
    Fail 'secondary seed sub-roots must remain below the secondary seed root'
}
Assert-Disjoint $seedCargoRoot 'primary Cargo seed' $seedLfsRoot 'primary LFS seed'
Assert-Disjoint $secondSeedCargoRoot 'secondary Cargo seed' $secondSeedLfsRoot 'secondary LFS seed'

$inputRoots = @(
    [pscustomobject]@{ Path = $repoRoot; Label = 'primary repository' },
    [pscustomobject]@{ Path = $secondRepoRoot; Label = 'secondary repository' },
    [pscustomobject]@{ Path = $seedRoot; Label = 'primary seed' },
    [pscustomobject]@{ Path = $secondSeedRoot; Label = 'secondary seed' }
)
for ($i = 0; $i -lt $inputRoots.Count; $i++) {
    for ($j = $i + 1; $j -lt $inputRoots.Count; $j++) {
        Assert-Disjoint $inputRoots[$i].Path $inputRoots[$i].Label $inputRoots[$j].Path $inputRoots[$j].Label
    }
}
$output = Resolve-ProspectiveOutput $OutputRoot
foreach ($input in $inputRoots) { Assert-Disjoint $output.Path 'final output path' $input.Path $input.Label }

Assert-NoDescendantPathAlias $repoRoot 'primary repository'
Assert-NoDescendantPathAlias $secondRepoRoot 'secondary repository'
Assert-NoDescendantPathAlias $seedCargoRoot 'primary Cargo seed'
Assert-NoDescendantPathAlias $seedLfsRoot 'primary LFS seed'
Assert-NoDescendantPathAlias $secondSeedCargoRoot 'secondary Cargo seed'
Assert-NoDescendantPathAlias $secondSeedLfsRoot 'secondary LFS seed'
Assert-B4NoDescendantHardLink $repoRoot 'primary repository'
Assert-B4NoDescendantHardLink $secondRepoRoot 'secondary repository'
Assert-B4NoDescendantHardLink $seedCargoRoot 'primary Cargo seed'
Assert-B4NoDescendantHardLink $seedLfsRoot 'primary LFS seed'
Assert-B4NoDescendantHardLink $secondSeedCargoRoot 'secondary Cargo seed'
Assert-B4NoDescendantHardLink $secondSeedLfsRoot 'secondary LFS seed'
$primaryGit = Get-GitEvidenceLines $repoRoot
$secondaryGit = Get-GitEvidenceLines $secondRepoRoot
if (($primaryGit -join "`n") -cne ($secondaryGit -join "`n")) { Fail 'the clean checkouts do not identify the same Git commit and tree' }

$guestReference = 'risczero/risc0-guest-builder@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3'
$hostReference = 'rust@sha256:294917190b5a3fed18d3303213943f40ec9b644b3cd6e5cdc8cd029334a770b3'
Assert-ExactLocalImage $guestReference
Assert-ExactLocalImage $hostReference
$runtimeExecutionRef = Assert-LocalRuntimeImage $RuntimeImage

$lockPath = Join-Path $output.Parent ".$($output.Name).b4.lock"
$lockStream = $null
$lockOwned = $false
$stagingRoot = $null
$workRoot = $null
$published = $false
$publicationOccurred = $false
$script:retainedQualifyingContainer = $false
$script:retainedQualifyingContainerName = $null
Initialize-B4ContainerGuard
try {
    $lockStream = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $lockOwned = $true
    $lockBytes = [System.Text.Encoding]::ASCII.GetBytes("eip0045-b4-publication-lock`n")
    $lockStream.Write($lockBytes, 0, $lockBytes.Length)
    $lockStream.Flush($true)
    if (Test-Path -LiteralPath $output.Path) { Fail 'final output directory appeared after publication lock acquisition' }

    $token = [Guid]::NewGuid().ToString('N')
    $workRoot = Join-Path $output.Parent ".$($output.Name).b4-work.$token"
    $stagingRoot = Join-Path $output.Parent ".$($output.Name).b4-staging.$token"
    New-Item -ItemType Directory -Path $workRoot | Out-Null
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    Reject-MountUnsafeValue $workRoot 'work root'
    Reject-MountUnsafeValue $stagingRoot 'evidence staging root'

    Write-BaseImageEvidence $guestReference $hostReference (Join-Path $stagingRoot 'base-images-inspect.txt')
    Write-RuntimeEvidence $RuntimeImage $runtimeExecutionRef (Join-Path $stagingRoot 'runtime-image-inspect.txt')
    Assert-LocalRuntimeImage $runtimeExecutionRef | Out-Null
    Invoke-B4BuildRun 'run-1' $repoRoot $seedCargoRoot $seedLfsRoot $stagingRoot $workRoot $runtimeExecutionRef
    Assert-LocalRuntimeImage $runtimeExecutionRef | Out-Null
    Invoke-B4BuildRun 'run-2' $secondRepoRoot $secondSeedCargoRoot $secondSeedLfsRoot $stagingRoot $workRoot $runtimeExecutionRef
    Assert-LocalRuntimeImage $runtimeExecutionRef | Out-Null

    Assert-FileIdentityEqual (Join-Path $stagingRoot 'run-1\guest.elf') (Join-Path $stagingRoot 'run-2\guest.elf') 'fresh builds produced different guest ELF bytes'
    Assert-FileIdentityEqual (Join-Path $stagingRoot 'run-1\image-id.bin') (Join-Path $stagingRoot 'run-2\image-id.bin') 'fresh builds produced different canonical image ID bytes'
    Assert-FileIdentityEqual (Join-Path $stagingRoot 'run-1\alternate-program-guest.elf') (Join-Path $stagingRoot 'run-2\alternate-program-guest.elf') 'fresh builds produced different alternate-program guest ELF bytes'
    Assert-FileIdentityEqual (Join-Path $stagingRoot 'run-1\alternate-program-image-id.bin') (Join-Path $stagingRoot 'run-2\alternate-program-image-id.bin') 'fresh builds produced different alternate-program image ID bytes'
    foreach ($evidence in @(
        'source-materialized-manifest.txt', 'source-checkout-admin-manifest.txt', 'workspace-source-manifest.txt', 'workspace-git.txt',
        'candidate-generator', 'image-id.hex', 'image-id-declaration.txt',
        'alternate-program-image-id.hex', 'alternate-program-image-id-declaration.txt',
        'source-git-observed.txt', 'host-toolchain-observed.txt',
        'guest-toolchain-observed.txt', 'build-policy.txt', 'resource-policy-observed.txt', 'build-environment.txt',
        'candidate-source-lock.json', 'cargo-metadata-generator-host.json', 'cargo-metadata-methods-build.json',
        'cargo-metadata-guest.json', 'cargo-closure-generator-host.json', 'cargo-closure-methods-build.json',
        'cargo-closure-guest.json', 'identity.txt'
    )) {
        Assert-FileIdentityEqual (Join-Path $stagingRoot "run-1\$evidence") (Join-Path $stagingRoot "run-2\$evidence") "fresh builds produced different $evidence evidence"
    }
    $run1Manifest = Get-TreeManifestLines (Join-Path $stagingRoot 'run-1')
    $run2Manifest = Get-TreeManifestLines (Join-Path $stagingRoot 'run-2')
    if (($run1Manifest -join "`n") -cne ($run2Manifest -join "`n")) {
        Fail 'fresh builds produced different complete run evidence trees'
    }
    Write-LfUtf8 (Join-Path $stagingRoot 'run-evidence-identity.txt') $run1Manifest
    Assert-LocalRuntimeImage $runtimeExecutionRef | Out-Null
    Assert-NoDescendantPathAlias $stagingRoot 'completed evidence staging tree'
    Write-EvidenceManifest $stagingRoot
    $manifestHash = (Get-FileHash -LiteralPath (Join-Path $stagingRoot 'evidence-manifest.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
    $guestHash = (Get-FileHash -LiteralPath (Join-Path $stagingRoot 'run-1\guest.elf') -Algorithm SHA256).Hash.ToLowerInvariant()
    $imageIdHash = (Get-FileHash -LiteralPath (Join-Path $stagingRoot 'run-1\image-id.bin') -Algorithm SHA256).Hash.ToLowerInvariant()
    $alternateProgramGuestHash = (Get-FileHash -LiteralPath (Join-Path $stagingRoot 'run-1\alternate-program-guest.elf') -Algorithm SHA256).Hash.ToLowerInvariant()
    $alternateProgramImageIdHash = (Get-FileHash -LiteralPath (Join-Path $stagingRoot 'run-1\alternate-program-image-id.bin') -Algorithm SHA256).Hash.ToLowerInvariant()
    $consumerImageId = [System.IO.File]::ReadAllBytes((Join-Path $stagingRoot 'run-1\image-id.bin'))
    $alternateProgramImageId = [System.IO.File]::ReadAllBytes((Join-Path $stagingRoot 'run-1\alternate-program-image-id.bin'))
    if (
        [Convert]::ToBase64String($consumerImageId) -ceq
        [Convert]::ToBase64String($alternateProgramImageId)
    ) {
        Fail 'alternate-program image ID equals the consumer image ID'
    }
    Write-LfUtf8 (Join-Path $stagingRoot 'B4-COMPLETE') @(
        'schema=eip0045-b4-build-completion-v2',
        'status=complete',
        'runCount=2',
        'inputIsolation=path-disjoint-standalone-clean-checkouts-private-object-stores-and-seeds',
        'executionIsolation=fresh-home-target-and-work-per-run-same-pinned-runtime',
        "runtimeManifest=$runtimeExecutionRef",
        "evidenceManifestSha256=$manifestHash",
        "guestElfSha256=$guestHash",
        "imageIdSha256=$imageIdHash",
        "alternateProgramGuestElfSha256=$alternateProgramGuestHash",
        "alternateProgramImageIdSha256=$alternateProgramImageIdHash"
    )
    if (Test-Path -LiteralPath $output.Path) { Fail 'final output directory appeared before atomic publication' }
    [System.IO.Directory]::Move($stagingRoot, $output.Path)
    $publicationOccurred = $true
    Assert-LocalRuntimeImage $runtimeExecutionRef | Out-Null
    $checkerTarget = Join-Path $workRoot 'run-1-target'
    $checkerBinary = Join-Path $checkerTarget 'debug\eip0045-reproduction'
    if (-not (Test-Path -LiteralPath $checkerBinary -PathType Leaf)) { Fail 'fresh-process B4 checker binary is absent' }
    $checkerContainerName = "eip0045-b4-checker-$([Guid]::NewGuid().ToString('N'))"
    $checkerHostDiagnostics = Join-Path $workRoot 'checker-host-diagnostics'
    Invoke-QualifyingContainer $checkerContainerName @(
        '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
        '--memory', '1g', '--memory-swap', '1g', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
        '--mount', "type=bind,src=$($output.Path),dst=/published,readonly",
        '--mount', "type=bind,src=$checkerTarget,dst=/checker-target,readonly",
        $runtimeExecutionRef, '/checker-target/debug/eip0045-reproduction', 'b4-build-check', '--root', '/published',
        '--allow-unanchored-inspection'
    ) $checkerHostDiagnostics
    Assert-LocalRuntimeImage $runtimeExecutionRef | Out-Null
    $published = $true
    Write-Output "B4 build: path-disjoint clean builds agree; complete evidence published at $($output.Path)"
} catch {
    $originalError = $_
    $diagnostics = $null
    if (Test-B4ContainerBindSourcesMustRemain) {
        try { Write-B4ContainerUncertainty -Reason 'runner-exited-before-removal-confirmed' } catch {
            Write-Warning $_.Exception.Message
        }
    }
    if ($null -ne $stagingRoot -and (Test-Path -LiteralPath $stagingRoot) -and $null -ne $workRoot -and (Test-Path -LiteralPath $workRoot)) {
        if (Test-B4ContainerBindSourcesMustRemain) {
            $diagnostics = $stagingRoot
        } else {
            $diagnostics = Join-Path $workRoot 'diagnostics-partial-evidence'
            if (-not (Test-Path -LiteralPath $diagnostics)) {
                try {
                    [System.IO.Directory]::Move($stagingRoot, $diagnostics)
                } catch {
                    try { Remove-OwnedTransientRoot $stagingRoot $output.Parent $output.Name 'staging' } catch { Write-Warning $_.Exception.Message }
                }
            }
        }
    }
    if ($publicationOccurred -and (Test-Path -LiteralPath $output.Path -PathType Container)) {
        Write-Warning "B4 published evidence remains at $($output.Path), but post-publication verification failed; treat it as unverified"
    }
    if ($null -ne $workRoot -and (Test-Path -LiteralPath $workRoot)) {
        Write-Warning "B4 failed; non-evidence diagnostics retained at $workRoot"
    }
    if ($script:retainedQualifyingContainer) {
        Write-Warning "B4 retained qualifying container $($script:retainedQualifyingContainerName); its original bind sources were not moved"
    } elseif (Test-B4ContainerBindSourcesMustRemain) {
        Write-Warning 'B4 qualifying container presence is uncertain; original bind sources were not moved'
    }
    if ($null -ne $diagnostics -and (Test-Path -LiteralPath $diagnostics -PathType Container)) {
        Write-Warning "B4 partial evidence retained at $diagnostics"
    }
    throw $originalError
} finally {
    if ($null -ne $lockStream) { $lockStream.Dispose() }
    if ($lockOwned -and (Test-Path -LiteralPath $lockPath)) {
        try { Remove-Item -LiteralPath $lockPath -Force } catch { Write-Warning $_.Exception.Message }
    }
    if ($published -and $null -ne $workRoot -and (Test-Path -LiteralPath $workRoot)) {
        try { Remove-OwnedTransientRoot $workRoot $output.Parent $output.Name 'work' } catch { Write-Warning $_.Exception.Message }
    }
}
