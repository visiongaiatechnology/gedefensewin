# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [long]$SourceDateEpoch = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Import-Module -Name (Join-Path $projectRoot 'tools\VgtSupplyChain.psm1') -Force
$version = Read-VgtVersion -ProjectRoot $projectRoot
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $projectRoot 'release' }
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$projectPath = [IO.Path]::GetFullPath($projectRoot)
$projectFull = $projectPath.TrimEnd('\') + '\'
$releasePath = [IO.Path]::GetFullPath((Join-Path $projectRoot 'release'))
$releaseFull = $releasePath.TrimEnd('\') + '\'
if ($outputRoot -eq $projectPath -or ($outputRoot.StartsWith($projectFull,[StringComparison]::OrdinalIgnoreCase) -and -not $outputRoot.StartsWith($releaseFull,[StringComparison]::OrdinalIgnoreCase) -and $outputRoot -ne $releasePath)) {
    throw [Security.SecurityException]::new('Source release output must not overwrite project source paths.')
}

if ($SourceDateEpoch -le 0) {
    $epochInfo = Get-VgtSourceDateEpoch -ProjectRoot $projectRoot
    $SourceDateEpoch = $epochInfo.Epoch
    if ($epochInfo.Source -eq 'changelog-latest-fallback') {
        Write-Warning ('SOURCE_DATE_EPOCH metadata file is missing; release timestamp derived from legacy changelog data ({0}). Add SOURCE_DATE_EPOCH for a first-class deterministic release date.' -f $epochInfo.Date)
    }
}
if ($SourceDateEpoch -lt 315532800) { throw [IO.InvalidDataException]::new('SOURCE_DATE_EPOCH predates the ZIP timestamp boundary.') }
$fixedTimestamp = [DateTimeOffset]::FromUnixTimeSeconds($SourceDateEpoch)

function Assert-VgtDeterministicZip {
    # Parses the ZIP central directory directly: proves that every entry is
    # stored (method 0), carries the fixed DOS timestamp and appears in the
    # expected ordinal order. ZipArchiveEntry.CompressedLength is not used
    # because .NET Framework reports a constant overhead for stored entries.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$ExpectedNames,
        [Parameter(Mandatory)][DateTimeOffset]$ExpectedTimestamp
    )
    if ($ExpectedTimestamp.Year -lt 1980) { throw [IO.InvalidDataException]::new('ZIP timestamp precedes the DOS epoch.') }
    $dosDate = ((($ExpectedTimestamp.Year - 1980) -shl 9) -bor ($ExpectedTimestamp.Month -shl 5) -bor $ExpectedTimestamp.Day)
    $dosTime = (($ExpectedTimestamp.Hour -shl 11) -bor ($ExpectedTimestamp.Minute -shl 5) -bor ([int][Math]::Floor($ExpectedTimestamp.Second / 2)))
    $fileStream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $reader = [IO.BinaryReader]::new($fileStream)
        $length = $fileStream.Length
        if ($length -lt 22) { throw [IO.InvalidDataException]::new('Source ZIP is too small.') }
        $tailLength = [int][Math]::Min(65557,[int]$length)
        $fileStream.Position = $length - $tailLength
        $tail = $reader.ReadBytes($tailLength)
        $eocdIndex = -1
        for ($i = $tail.Length - 22; $i -ge 0; $i--) {
            if ($tail[$i] -eq 0x50 -and $tail[$i+1] -eq 0x4b -and $tail[$i+2] -eq 0x05 -and $tail[$i+3] -eq 0x06) { $eocdIndex = $i; break }
        }
        if ($eocdIndex -lt 0) { throw [IO.InvalidDataException]::new('Source ZIP end-of-central-directory record is missing.') }
        $totalEntries = [BitConverter]::ToUInt16($tail,$eocdIndex + 10)
        $centralDirectoryOffset = [BitConverter]::ToUInt32($tail,$eocdIndex + 16)
        if ($totalEntries -ne $ExpectedNames.Count) { throw [IO.InvalidDataException]::new(('Source ZIP entry count mismatch: {0} vs {1}.' -f $totalEntries,$ExpectedNames.Count)) }
        $fileStream.Position = [long]$centralDirectoryOffset
        for ($index = 0; $index -lt $totalEntries; $index++) {
            $header = $reader.ReadBytes(46)
            if ($header.Length -ne 46) { throw [IO.InvalidDataException]::new('Source ZIP central directory is truncated.') }
            if ([BitConverter]::ToUInt32($header,0) -ne 0x02014b50) { throw [IO.InvalidDataException]::new('Source ZIP central directory signature is invalid.') }
            $method = [BitConverter]::ToUInt16($header,10)
            $entryTime = [BitConverter]::ToUInt16($header,12)
            $entryDate = [BitConverter]::ToUInt16($header,14)
            if ($method -ne 0) { throw [IO.InvalidDataException]::new(('Source ZIP entry is compressed despite the NoCompression contract: {0}' -f $ExpectedNames[$index])) }
            if ($entryTime -ne $dosTime -or $entryDate -ne $dosDate) { throw [IO.InvalidDataException]::new(('Source ZIP entry timestamp is not deterministic: {0}' -f $ExpectedNames[$index])) }
            $nameLength = [BitConverter]::ToUInt16($header,28)
            $extraLength = [BitConverter]::ToUInt16($header,30)
            $commentLength = [BitConverter]::ToUInt16($header,32)
            $nameBytes = $reader.ReadBytes($nameLength)
            $entryName = [Text.Encoding]::UTF8.GetString($nameBytes)
            if ($entryName -ne $ExpectedNames[$index]) { throw [IO.InvalidDataException]::new(('Source ZIP entry order/path mismatch: {0} vs {1}.' -f $entryName,$ExpectedNames[$index])) }
            $skip = $extraLength + $commentLength
            if ($skip -gt 0) {
                $skipped = $reader.ReadBytes($skip)
                if ($skipped.Length -ne $skip) { throw [IO.InvalidDataException]::new('Source ZIP central directory extra data is truncated.') }
            }
        }
    } finally {
        if ($reader) { $reader.Dispose() }
        $fileStream.Dispose()
    }
}

# The SBOM is a source-release input: regenerate it deterministically from the
# working tree before the manifest so the shipped zip never contains a stale
# component inventory.
$sbomGenerator = Join-Path $projectRoot 'tools\New-VgtSbom.ps1'
if (Test-Path -LiteralPath $sbomGenerator -PathType Leaf) {
    & $sbomGenerator
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'sbom\gedefense-windows.cdx.json') -PathType Leaf)) { throw [IO.FileNotFoundException]::new('SBOM generation did not produce sbom/gedefense-windows.cdx.json.') }
}

$files = @(Get-VgtSourceFileList -ProjectRoot $projectRoot)
if ($files.Count -lt 50 -or $files.Count -gt 2000) { throw [IO.InvalidDataException]::new('Source release file count violated the expected boundary.') }

# Exactly one authoritative integrity manifest: the stale FULL_SOURCE_SHA256.txt
# baseline is excluded and must not reappear in the distribution tree.
$staleManifestPath = Join-Path $projectRoot 'FULL_SOURCE_SHA256.txt'
if (Test-Path -LiteralPath $staleManifestPath) { throw [IO.InvalidDataException]::new('Stale FULL_SOURCE_SHA256.txt is present in the source tree; remove it (authoritative manifest is SOURCE-MANIFEST.sha256).') }
$rootManifests = @(Get-ChildItem -LiteralPath $projectRoot -File -Force | Where-Object { $_.Name -match '(?i)sha256|checksum' })
foreach ($rootManifest in $rootManifests) {
    if ($rootManifest.Name -ne 'SOURCE-MANIFEST.sha256') { throw [IO.InvalidDataException]::new(('Competing integrity manifest in the source tree: {0}' -f $rootManifest.Name)) }
}

$reparse = @($files | Where-Object { ([IO.File]::GetAttributes($_.FullName) -band [IO.FileAttributes]::ReparsePoint) })
if ($reparse.Count -ne 0) { throw [Security.SecurityException]::new('Source release contains a reparse-point file.') }
foreach ($file in $files) {
    $forbiddenReason = Get-VgtDistributionForbiddenReason -RelativePath $file.Relative
    if ($forbiddenReason) { throw [IO.InvalidDataException]::new(('Forbidden distribution artifact entered the source release: {0} ({1})' -f $file.Relative,$forbiddenReason)) }
}

# The manifest uses the same deterministic enumeration/ordinal ordering as the
# provenance artifact, so both bind the identical byte set.
$manifestInfo = Write-VgtSourceManifest -ProjectRoot $projectRoot

# Re-enumerate so the freshly generated manifest is shipped, while intentionally
# excluding it from self-hashing.
$shipFiles = [Collections.Generic.List[string]]::new()
foreach ($file in $files) { $shipFiles.Add($file.Relative) }
$shipFiles.Add('SOURCE-MANIFEST.sha256')
$shipRelative = [string[]]@($shipFiles.ToArray())
[Array]::Sort($shipRelative,[StringComparer]::Ordinal)
$filesByRelative = @{}
foreach ($file in $files) { $filesByRelative[$file.Relative] = $file }
$shipEntries = [Collections.Generic.List[object]]::new()
foreach ($relative in $shipRelative) {
    if ($relative -eq 'SOURCE-MANIFEST.sha256') {
        $manifestItem = Get-Item -LiteralPath $manifestInfo.Path
        $shipEntries.Add([pscustomobject][ordered]@{ Relative = $relative; FullName = $manifestItem.FullName; Length = [long]$manifestItem.Length })
    } else {
        $shipEntries.Add($filesByRelative[$relative])
    }
}

New-Item -Path $outputRoot -ItemType Directory -Force | Out-Null
$archivePath = Join-Path $outputRoot ("VGT_GeDefense_Windows_{0}_Source.zip" -f $version)
$checksumPath = "$archivePath.sha256"
if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
if (Test-Path -LiteralPath $checksumPath) { Remove-Item -LiteralPath $checksumPath -Force }

if (-not ('VgtDeterministicZip' -as [type])) {
    # The .NET ZipArchive API cannot emit stored (method 0) entries; its
    # "NoCompression" level still produces a Deflate stream with stored blocks.
    # A small deterministic writer guarantees method 0, fixed DOS timestamps and
    # ordinal ordering (SC-FIND-005), and is fast enough for the 70 MiB dataset.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;

public static class VgtDeterministicZip
{
    private static readonly uint[] CrcTable = BuildTable();

    private static uint[] BuildTable()
    {
        uint[] table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
            {
                c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        return table;
    }

    private static uint UpdateCrc(uint crc, byte[] buffer, int count)
    {
        uint c = crc;
        for (int i = 0; i < count; i++)
        {
            c = CrcTable[(c ^ buffer[i]) & 0xFF] ^ (c >> 8);
        }
        return c;
    }

    private static void WriteU16(Stream s, ushort v)
    {
        s.WriteByte((byte)(v & 0xFF));
        s.WriteByte((byte)((v >> 8) & 0xFF));
    }

    private static void WriteU32(Stream s, uint v)
    {
        WriteU16(s, (ushort)(v & 0xFFFF));
        WriteU16(s, (ushort)((v >> 16) & 0xFFFF));
    }

    public static int Write(string outputPath, string[] filePaths, string[] entryNames, DateTime timestampUtc)
    {
        if (filePaths == null || entryNames == null || filePaths.Length != entryNames.Length)
        {
            throw new ArgumentException("file/name mismatch");
        }
        if (timestampUtc.Year < 1980)
        {
            throw new ArgumentException("timestamp before DOS epoch");
        }
        ushort dosDate = (ushort)(((timestampUtc.Year - 1980) << 9) | (timestampUtc.Month << 5) | timestampUtc.Day);
        ushort dosTime = (ushort)((timestampUtc.Hour << 11) | (timestampUtc.Minute << 5) | (timestampUtc.Second / 2));
        long[] localOffsets = new long[filePaths.Length];
        uint[] crcs = new uint[filePaths.Length];
        long[] sizes = new long[filePaths.Length];
        using (FileStream output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
        {
            for (int i = 0; i < filePaths.Length; i++)
            {
                byte[] nameBytes = Encoding.UTF8.GetBytes(entryNames[i]);
                localOffsets[i] = output.Position;
                uint crc = 0xFFFFFFFFu;
                long size = 0;
                byte[] buffer = new byte[1 << 20];
                using (FileStream input = new FileStream(filePaths[i], FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
                {
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        crc = UpdateCrc(crc, buffer, read);
                        size += read;
                    }
                }
                crc ^= 0xFFFFFFFFu;
                crcs[i] = crc;
                sizes[i] = size;
                WriteU32(output, 0x04034B50u);
                WriteU16(output, 20);
                WriteU16(output, 0x0800);
                WriteU16(output, 0);
                WriteU16(output, dosTime);
                WriteU16(output, dosDate);
                WriteU32(output, crc);
                WriteU32(output, (uint)size);
                WriteU32(output, (uint)size);
                WriteU16(output, (ushort)nameBytes.Length);
                WriteU16(output, 0);
                output.Write(nameBytes, 0, nameBytes.Length);
                using (FileStream data = new FileStream(filePaths[i], FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
                {
                    int read;
                    while ((read = data.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        output.Write(buffer, 0, read);
                    }
                }
            }
            long centralStart = output.Position;
            for (int i = 0; i < filePaths.Length; i++)
            {
                byte[] nameBytes = Encoding.UTF8.GetBytes(entryNames[i]);
                WriteU32(output, 0x02014B50u);
                WriteU16(output, 20);
                WriteU16(output, 20);
                WriteU16(output, 0x0800);
                WriteU16(output, 0);
                WriteU16(output, dosTime);
                WriteU16(output, dosDate);
                WriteU32(output, crcs[i]);
                WriteU32(output, (uint)sizes[i]);
                WriteU32(output, (uint)sizes[i]);
                WriteU16(output, (ushort)nameBytes.Length);
                WriteU16(output, 0);
                WriteU16(output, 0);
                WriteU16(output, 0);
                WriteU16(output, 0);
                WriteU32(output, 0);
                WriteU32(output, (uint)localOffsets[i]);
                output.Write(nameBytes, 0, nameBytes.Length);
            }
            long centralEnd = output.Position;
            WriteU32(output, 0x06054B50u);
            WriteU16(output, 0);
            WriteU16(output, 0);
            WriteU16(output, (ushort)filePaths.Length);
            WriteU16(output, (ushort)filePaths.Length);
            WriteU32(output, (uint)(centralEnd - centralStart));
            WriteU32(output, (uint)centralStart);
            WriteU16(output, 0);
        }
        return filePaths.Length;
    }
}
'@
}
$entryFilePaths = [Collections.Generic.List[string]]::new()
$zipEntryNames = [Collections.Generic.List[string]]::new()
$prefix = "GeDefense-Windows-$version/"
foreach ($file in $shipEntries) {
    $entryFilePaths.Add($file.FullName)
    $zipEntryNames.Add($prefix + $file.Relative)
}
$writtenEntries = [VgtDeterministicZip]::Write($archivePath,$entryFilePaths.ToArray(),$zipEntryNames.ToArray(),$fixedTimestamp.UtcDateTime)
if ($writtenEntries -ne $shipEntries.Count) { throw [IO.InvalidDataException]::new('Deterministic ZIP writer produced an unexpected entry count.') }

# Reproducibility regression: parse the archive central directory and prove
# stored-only entries, fixed timestamps and ordinal entry order instead of
# trusting the writer flags.
$expectedEntryNames = [Collections.Generic.List[string]]::new()
foreach ($shipEntry in $shipEntries) { $expectedEntryNames.Add(("GeDefense-Windows-$version/" + $shipEntry.Relative)) }
Assert-VgtDeterministicZip -Path $archivePath -ExpectedNames $expectedEntryNames.ToArray() -ExpectedTimestamp $fixedTimestamp

$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($checksumPath,"$archiveHash  $([IO.Path]::GetFileName($archivePath))`n",[Text.UTF8Encoding]::new($false))

# Source-bound provenance artifact (unsigned by design; verifiable offline).
$provenancePath = Join-Path $outputRoot ("GeDefense-Provenance-v{0}.json" -f $version)
$provenanceGenerator = Join-Path $projectRoot 'tools\New-VgtProvenance.ps1'
$provenanceVerifier = Join-Path $projectRoot 'tools\Test-VgtProvenance.ps1'
if (Test-Path -LiteralPath $provenanceGenerator -PathType Leaf) {
    & $provenanceGenerator -OutputPath $provenancePath -SourceArchive $archivePath -RequireSourceManifest
    if (Test-Path -LiteralPath $provenanceVerifier -PathType Leaf) {
        & $provenanceVerifier -Path $provenancePath -RequireSourceManifest
    }
} else {
    throw [IO.FileNotFoundException]::new('tools/New-VgtProvenance.ps1 is missing; reproducible provenance is mandatory for a release.')
}

[pscustomobject]@{
    Status = 'PASS'
    Version = $version
    Files = $files.Count
    ZipEntries = $shipEntries.Count
    SourceDateEpoch = $SourceDateEpoch
    Compression = 'stored'
    Manifest = $manifestInfo.Path
    ManifestDigest = $manifestInfo.Digest
    Archive = $archivePath
    SHA256 = $archiveHash
    Provenance = $provenancePath
}
