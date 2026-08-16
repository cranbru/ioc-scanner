<#
.SYNOPSIS
    IOC Scanner v2.0 - scans a drive for a known set of Indicators of Compromise
    (filename / MD5 / SHA-256 / domain / IP), and separately checks forensic
    artifacts for evidence that an IOC WAS present and has since been deleted.

.DESCRIPTION
    Read-only DFIR detection tool. Two independent passes:

    PASS 1 - File-system IOC scan (as v1.0):
        - Walks -ScanPath, matches known filenames, hashes candidates (MD5+SHA256)
        - CONFIRMED IOC MATCH (name+hash) / SUSPICIOUS NAME MATCH (name only)

    PASS 2 - Network IOC scan (new):
        - Checks DNS client resolver cache for known-bad domains/IPs
        - Checks the hosts file for IOC domain/IP entries (classic redirect technique)
        - Greps browser history DBs (Chrome/Edge/Firefox SQLite files) for the domain

    PASS 3 - "Was it here and is it gone now?" evidence pass (new):
        A deleted file has no bytes to hash, so presence has to be inferred from
        artifacts that outlive deletion:
        - Prefetch (C:\Windows\Prefetch\*.pf)      -> proves the exe RAN
        - Recycle Bin ($Recycle.Bin)               -> proves it existed & was deleted (not wiped)
        - Event Logs (Sysmon 1/3/11 if installed, else Security 4688 if auditing is on)
                                                     -> process creation / network / file-create refs
        Each IOC is classified per artifact type as:
            PRESENT NOW   - live match found in Pass 1
            DELETED (evidence found)  - no live file, but Prefetch/RecycleBin/EventLog
                                         shows it existed at some point
            NO TRACE      - nothing found anywhere checked

        NOTE: Amcache.hve and ShimCache/AppCompatCache are binary registry
        structures. Correctly parsing them needs a real parser, not a
        hand-rolled one - this script does NOT attempt to parse them itself.
        Instead it flags their presence/location and tells you to run
        Eric Zimmerman's AmcacheParser / AppCompatCacheParser (or KAPE) against
        them, which is the right tool for that specific artifact.

    Still does NO file writes/deletes/executes outside its own report/log
    files, NO network calls out (DNS cache/hosts/history are read locally),
    and NO process injection or security-tool modification.

.PARAMETER ScanPath
    Root path to scan for file IOCs. Default: C:\

.PARAMETER OutputDir
    Where to write the report/log/CSV. Default: Desktop, falling back to
    script folder, then %TEMP%.

.PARAMETER FullHashScan
    Hash EVERY file, not just filename candidates. Prompts unless -Force.

.PARAMETER ExcludePaths
    Path prefixes to skip entirely.

.PARAMETER SkipNetworkIOCs
    Skip Pass 2 (DNS cache / hosts / browser history).

.PARAMETER SkipEvidencePass
    Skip Pass 3 (Prefetch / Recycle Bin / Event Log deleted-evidence check).

.PARAMETER Force
    Suppress interactive prompts.

.PARAMETER OpenReport
    Auto-open the HTML report when done. Default: $true.

.EXAMPLE
    .\IOC_Scanner_v2.ps1
    Fast filename scan + network IOC check + deleted-evidence check.

.EXAMPLE
    .\IOC_Scanner_v2.ps1 -FullHashScan -Force -OutputDir D:\CaseFiles\Case001

.NOTES
    Run elevated for full coverage (Prefetch, other users' Recycle Bins,
    Security event log, protected folders). Non-elevated runs still work;
    inaccessible items are logged as skipped, not fatal.
#>

[CmdletBinding()]
param(
    [string]$ScanPath = 'C:\',
    [string]$OutputDir,
    [switch]$FullHashScan,
    [string[]]$ExcludePaths = @(),
    [switch]$SkipNetworkIOCs,
    [switch]$SkipEvidencePass,
    [switch]$Force,
    [bool]$OpenReport = $true
)

# ======================================================================
#  SETUP
# ======================================================================
$ErrorActionPreference = 'Continue'
$ScriptVersion = '2.0'
$Timestamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
$HostName      = $env:COMPUTERNAME
$RunAsUser     = "$env:USERDOMAIN\$env:USERNAME"

$Global:ScanErrors      = New-Object System.Collections.Generic.List[string]
$Global:MatchResults    = New-Object System.Collections.Generic.List[object]   # Pass 1 - file hash/name matches
$Global:NetworkMatches  = New-Object System.Collections.Generic.List[object]   # Pass 2 - domain/IP matches
$Global:EvidenceResults = New-Object System.Collections.Generic.List[object]   # Pass 3 - deleted-evidence matches
$Global:ExitCode        = 0

# ----------------------------------------------------------------------
# Known file IOC set (filename + MD5 + SHA-256)
# [REDACTED FOR PUBLICATION — populate with your own case-specific IOCs]
# ----------------------------------------------------------------------
$IOCs = @(
    [PSCustomObject]@{ Name = '<filename>.exe'; MD5 = '<redacted>'; SHA256 = '<redacted>' }
    # ... additional entries
)

# ----------------------------------------------------------------------
# Known network IOC set (domain + IPs).
# [REDACTED FOR PUBLICATION — populate with your own case-specific IOCs]
# ----------------------------------------------------------------------
$NetworkIOCs = @(
    [PSCustomObject]@{ Type = 'Domain'; Value = '<redacted>'; Note = '<context note>' }
    # ... additional entries
)

# ----------------------------------------------------------------------
# Internal hosts of interest (RFC1918). These are NOT scanned the same
# way as external IOCs - a single endpoint has no visibility into other
# hosts' traffic. What we CAN do locally: (1) flag if THIS machine's own
# interfaces match one of them, (2) check the local ARP cache for recent
# contact with them, (3) grep local firewall/event logs for them.
# True lateral-movement mapping needs switch/firewall/DHCP logs or a
# SIEM query across the fleet - the report calls this out explicitly
# rather than implying full coverage from one endpoint.
# ----------------------------------------------------------------------
$InternalHostsOfInterest = @(
    # [REDACTED FOR PUBLICATION]
)

# ----------------------------------------------------------------------
# Name-only watchlist: filenames flagged as suspicious in this case but
# with no known-good hash yet. No hash to confirm against, so these can
# only ever produce SUSPICIOUS NAME MATCH, never CONFIRMED - hash them
# from any hit and add the hash to $IOCs above once verified, so future
# runs get a true positive instead.
# ----------------------------------------------------------------------
$NameOnlyWatchlist = @(
    # [REDACTED FOR PUBLICATION]
)

$IOCByName   = @{}
$IOCByMD5    = @{}
$IOCBySHA256 = @{}
foreach ($ioc in $IOCs) {
    $nameKey = $ioc.Name.ToLowerInvariant()
    if (-not $IOCByName.ContainsKey($nameKey)) {
        $IOCByName[$nameKey] = New-Object System.Collections.Generic.List[object]
    }
    $IOCByName[$nameKey].Add($ioc)
    $IOCByMD5[$ioc.MD5.ToLowerInvariant()]       = $ioc
    $IOCBySHA256[$ioc.SHA256.ToLowerInvariant()] = $ioc
}
foreach ($n in $NameOnlyWatchlist) {
    $key = $n.ToLowerInvariant()
    if (-not $IOCByName.ContainsKey($key)) {
        $IOCByName[$key] = New-Object System.Collections.Generic.List[object]
    }
}

# ======================================================================
#  HELPER: pick a writable output folder, with fallbacks
# ======================================================================
function Get-WritableOutputDir {
    param([string]$Preferred)

    $candidates = @()
    if ($Preferred) { $candidates += $Preferred }
    $candidates += (Join-Path $env:USERPROFILE 'Desktop')
    if ($PSScriptRoot) { $candidates += $PSScriptRoot }
    $candidates += $env:TEMP

    foreach ($c in $candidates) {
        try {
            if (-not (Test-Path -LiteralPath $c)) {
                New-Item -ItemType Directory -Path $c -Force -ErrorAction Stop | Out-Null
            }
            $probe = Join-Path $c ".ioc_write_test_$Timestamp.tmp"
            Set-Content -LiteralPath $probe -Value 'ok' -ErrorAction Stop
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
            return $c
        } catch {
            continue
        }
    }
    throw "No writable output location found (tried: $($candidates -join ', '))"
}

# ======================================================================
#  HELPER: resilient, queue-based directory walker
# ======================================================================
function Get-FilesSafe {
    param([Parameter(Mandatory)][string]$RootPath, [string[]]$SkipPrefixes = @())

    $dirQueue = New-Object System.Collections.Generic.Queue[string]
    $dirQueue.Enqueue($RootPath)

    while ($dirQueue.Count -gt 0) {
        $currentDir = $dirQueue.Dequeue()

        $skip = $false
        foreach ($p in $SkipPrefixes) {
            if ($p -and $currentDir.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break }
        }
        if ($skip) { continue }

        $entries = $null
        try {
            $entries = [System.IO.Directory]::EnumerateFileSystemEntries($currentDir)
        } catch {
            $Global:ScanErrors.Add("[DIR-ACCESS] $currentDir :: $($_.Exception.GetType().Name): $($_.Exception.Message)")
            continue
        }

        try {
            foreach ($entry in $entries) {
                $attr = $null
                try {
                    $attr = [System.IO.File]::GetAttributes($entry)
                } catch {
                    $Global:ScanErrors.Add("[ATTR-ACCESS] $entry :: $($_.Exception.GetType().Name): $($_.Exception.Message)")
                    continue
                }

                $isDir     = [bool]($attr -band [System.IO.FileAttributes]::Directory)
                $isReparse = [bool]($attr -band [System.IO.FileAttributes]::ReparsePoint)

                if ($isDir) {
                    if (-not $isReparse) { $dirQueue.Enqueue($entry) }
                } else {
                    Write-Output $entry
                }
            }
        } catch {
            $Global:ScanErrors.Add("[DIR-ITER] $currentDir :: $($_.Exception.GetType().Name): $($_.Exception.Message)")
        }
    }
}

# ======================================================================
#  HELPER: single-pass MD5 + SHA-256
# ======================================================================
function Get-DualHash {
    param([Parameter(Mandatory)][string]$Path)

    $stream = $null
    $md5 = $null
    $sha256 = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        )
        $md5    = [System.Security.Cryptography.MD5]::Create()
        $sha256 = [System.Security.Cryptography.SHA256]::Create()

        $buffer = New-Object byte[] (1MB)
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $md5.TransformBlock($buffer, 0, $read, $null, 0)    | Out-Null
            $sha256.TransformBlock($buffer, 0, $read, $null, 0) | Out-Null
        }
        $md5.TransformFinalBlock([byte[]]@(), 0, 0)    | Out-Null
        $sha256.TransformFinalBlock([byte[]]@(), 0, 0) | Out-Null

        $md5Hex    = [System.BitConverter]::ToString($md5.Hash).Replace('-', '').ToLowerInvariant()
        $sha256Hex = [System.BitConverter]::ToString($sha256.Hash).Replace('-', '').ToLowerInvariant()

        return [PSCustomObject]@{ MD5 = $md5Hex; SHA256 = $sha256Hex }
    } catch {
        $Global:ScanErrors.Add("[HASH] $Path :: $($_.Exception.GetType().Name): $($_.Exception.Message)")
        return $null
    } finally {
        if ($stream)  { $stream.Dispose() }
        if ($md5)     { $md5.Dispose() }
        if ($sha256)  { $sha256.Dispose() }
    }
}

function Escape-Html([string]$s) {
    if ($null -eq $s) { return '' }
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

# ======================================================================
#  HELPER: word-boundary-anchored IOC name match
# ----------------------------------------------------------------------
#  Matches the FULL filename (with extension), anchored so it can't hit
#  as a bare substring of an unrelated token. Without this, a name like
#  'cmd.bat' matched on its extension-stripped basename ('cmd') would
#  match almost every PowerShell script block ever logged, since "cmd"
#  is a substring of Invoke-Command, -Command, cmdlet, Get-Command, etc.
#  Always pass the full watched name (with extension) in here - never a
#  GetFileNameWithoutExtension() result.
# ======================================================================
function Test-IOCNameMatch {
    param([string]$Text, [string]$Name)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Name)) { return $false }
    $pattern = '(?i)(?<![\w.-])' + [regex]::Escape($Name) + '(?![\w.-])'
    return [bool]([regex]::Match($Text, $pattern).Success)
}

# ======================================================================
#  PASS 2: Network IOC checks (DNS cache, hosts file, browser history)
# ======================================================================
function Invoke-NetworkIOCScan {

    # --- DNS client resolver cache ---
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction Stop
        foreach ($entry in $dnsCache) {
            foreach ($ioc in $NetworkIOCs) {
                $hit = $false
                if ($ioc.Type -eq 'Domain' -and $entry.Entry -match [regex]::Escape($ioc.Value)) { $hit = $true }
                if ($ioc.Type -eq 'IP' -and $entry.Data -eq $ioc.Value) { $hit = $true }
                if ($hit) {
                    $Global:NetworkMatches.Add([PSCustomObject]@{
                        Source   = 'DNS Client Cache'
                        IOCType  = $ioc.Type
                        IOCValue = $ioc.Value
                        Detail   = "Entry: $($entry.Entry)  Data: $($entry.Data)  RecordType: $($entry.Type)"
                    })
                }
            }
        }
    } catch {
        $Global:ScanErrors.Add("[DNS-CACHE] $($_.Exception.Message)")
    }

    # --- hosts file ---
    try {
        $hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
        if (Test-Path -LiteralPath $hostsPath) {
            $hostsLines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop
            foreach ($line in $hostsLines) {
                if ($line.TrimStart().StartsWith('#')) { continue }
                foreach ($ioc in $NetworkIOCs) {
                    if ($line -match [regex]::Escape($ioc.Value)) {
                        $Global:NetworkMatches.Add([PSCustomObject]@{
                            Source   = 'hosts file'
                            IOCType  = $ioc.Type
                            IOCValue = $ioc.Value
                            Detail   = "Line: $($line.Trim())"
                        })
                    }
                }
            }
        }
    } catch {
        $Global:ScanErrors.Add("[HOSTS-FILE] $($_.Exception.Message)")
    }

    # --- Browser history (Chrome / Edge / Firefox SQLite) ---
    # Uses a lightweight raw-byte scan for the domain string rather than a full
    # SQLite parse, since the DBs are usually locked while the browser runs and
    # a byte-level grep across an ASCII/UTF-8-ish column is enough to flag a hit
    # for follow-up with a proper SQLite reader (e.g. DB Browser for SQLite).
    $historyPaths = @()
    $userDirs = @()
    try { $userDirs = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue } catch {}
    foreach ($u in $userDirs) {
        $historyPaths += Join-Path $u.FullName 'AppData\Local\Google\Chrome\User Data\Default\History'
        $historyPaths += Join-Path $u.FullName 'AppData\Local\Microsoft\Edge\User Data\Default\History'
        $historyPaths += Join-Path $u.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
    }

    foreach ($path in $historyPaths) {
        try {
            if ($path -like '*Firefox\Profiles') {
                if (-not (Test-Path -LiteralPath $path)) { continue }
                $places = Get-ChildItem -LiteralPath $path -Filter 'places.sqlite' -Recurse -ErrorAction SilentlyContinue
                foreach ($p in $places) {
                    Search-BrowserDbBytes -DbPath $p.FullName -SourceLabel "Firefox history ($($p.FullName))"
                }
            } else {
                if (-not (Test-Path -LiteralPath $path)) { continue }
                Search-BrowserDbBytes -DbPath $path -SourceLabel "$(Split-Path $path -Parent) History"
            }
        } catch {
            $Global:ScanErrors.Add("[BROWSER-HISTORY] $path :: $($_.Exception.Message)")
        }
    }

    # --- Internal hosts of interest: is THIS box one of them? has it talked to one? ---
    try {
        $localIps = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        foreach ($ip in $InternalHostsOfInterest) {
            if ($localIps -contains $ip) {
                $Global:NetworkMatches.Add([PSCustomObject]@{
                    Source = 'Local interface'; IOCType = 'Internal IP'; IOCValue = $ip
                    Detail = 'THIS machine currently holds this IP - it is one of the hosts of interest, not just a peer of one'
                })
            }
        }
    } catch {
        $Global:ScanErrors.Add("[LOCAL-IP] $($_.Exception.Message)")
    }

    try {
        $arpEntries = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($entry in $arpEntries) {
            if ($InternalHostsOfInterest -contains $entry.IPAddress) {
                $Global:NetworkMatches.Add([PSCustomObject]@{
                    Source = 'ARP cache'; IOCType = 'Internal IP'; IOCValue = $entry.IPAddress
                    Detail = "MAC: $($entry.LinkLayerAddress)  State: $($entry.State)  -- ARP cache is short-lived (minutes), a miss here does NOT rule out past contact"
                })
            }
        }
    } catch {
        $Global:ScanErrors.Add("[ARP-CACHE] $($_.Exception.Message)")
    }

    if ($InternalHostsOfInterest.Count -gt 0) {
        $Global:NetworkMatches.Add([PSCustomObject]@{
            Source = 'N/A - reminder'; IOCType = 'Internal IP'; IOCValue = ($InternalHostsOfInterest -join ', ')
            Detail = 'Single-endpoint ARP/local-IP checks have limited visibility into internal traffic. For real lateral-movement mapping, correlate these IPs against firewall/switch logs, DHCP lease tables, or a SIEM query across the fleet.'
        })
    }
}

function Search-BrowserDbBytes {
    param([string]$DbPath, [string]$SourceLabel)
    try {
        # Copy first, since the live DB is often locked by the running browser
        $tmp = Join-Path $env:TEMP "iocscan_$([guid]::NewGuid().ToString('N')).sqlite"
        Copy-Item -LiteralPath $DbPath -Destination $tmp -ErrorAction Stop
        $bytes = [System.IO.File]::ReadAllBytes($tmp)
        $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
        foreach ($ioc in ($NetworkIOCs | Where-Object { $_.Type -eq 'Domain' })) {
            if ($text -match [regex]::Escape($ioc.Value)) {
                $Global:NetworkMatches.Add([PSCustomObject]@{
                    Source   = $SourceLabel
                    IOCType  = 'Domain'
                    IOCValue = $ioc.Value
                    Detail   = 'Domain string found in browser history database (raw byte scan)'
                })
            }
        }
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        $Global:ScanErrors.Add("[BROWSER-DB] $DbPath :: $($_.Exception.Message)")
    }
}

# ======================================================================
#  PASS 3: "was it here and is it gone now" evidence pass
# ======================================================================
function Invoke-EvidencePass {

    $iocNameKeys = ($IOCs | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name).ToLowerInvariant() }) +
                   ($NameOnlyWatchlist | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_).ToLowerInvariant() }) |
                   Select-Object -Unique

    # --- Prefetch: proves a binary EXECUTED, survives deletion of the exe ---
    try {
        $prefetchDir = "$env:WINDIR\Prefetch"
        if (Test-Path -LiteralPath $prefetchDir) {
            $pfFiles = Get-ChildItem -LiteralPath $prefetchDir -Filter '*.pf' -ErrorAction SilentlyContinue
            foreach ($pf in $pfFiles) {
                foreach ($key in $iocNameKeys) {
                    if ($pf.Name.ToLowerInvariant() -like "$key-*.pf") {
                        $Global:EvidenceResults.Add([PSCustomObject]@{
                            IOCName    = $key
                            Artifact   = 'Prefetch'
                            Status     = 'DELETED (evidence found)'
                            Detail     = "$($pf.Name)  LastRun(file mtime): $($pf.LastWriteTime)"
                        })
                    }
                }
            }
        } else {
            $Global:ScanErrors.Add("[PREFETCH] Prefetch folder not found or inaccessible (needs elevation / Prefetch may be disabled)")
        }
    } catch {
        $Global:ScanErrors.Add("[PREFETCH] $($_.Exception.Message)")
    }

    # --- Recycle Bin: proves it existed and was deleted (not securely wiped) ---
    $allWatchedNames = @($IOCs | ForEach-Object { $_.Name }) + $NameOnlyWatchlist
    try {
        $recycleRoots = Get-ChildItem 'C:\$Recycle.Bin' -Directory -Force -ErrorAction SilentlyContinue
        foreach ($rb in $recycleRoots) {
            $items = Get-ChildItem -LiteralPath $rb.FullName -Force -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                foreach ($wname in $allWatchedNames) {
                    if ($item.Name -ieq $wname -or $item.Name -like "*$wname") {
                        $Global:EvidenceResults.Add([PSCustomObject]@{
                            IOCName  = $wname
                            Artifact = 'Recycle Bin'
                            Status   = 'DELETED (evidence found)'
                            Detail   = "$($item.FullName)  Deleted(mtime): $($item.LastWriteTime)"
                        })
                    }
                }
            }
        }
    } catch {
        $Global:ScanErrors.Add("[RECYCLEBIN] $($_.Exception.Message)")
    }

    # --- Event Logs: Sysmon (1=process create, 3=network connect, 11=file create) if present, else Security 4688 ---
    # For Event ID 3 (network connect) specifically, we pull the actual DestinationIp/
    # DestinationPort out of the event's structured data - that's the "who did it talk
    # to" proof, not just "this ran once."
    try {
        $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
        if ($sysmonLog -and $sysmonLog.RecordCount -gt 0) {
            $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue -MaxEvents 20000 |
                Where-Object { $_.Id -in 1,3,11 }
            foreach ($ev in $events) {
                $xml = $null
                try { $xml = [xml]$ev.ToXml() } catch { $xml = $null }
                $eventData = @{}
                if ($xml) {
                    foreach ($d in $xml.Event.EventData.Data) { $eventData[$d.Name] = $d.'#text' }
                }
                $imageVal = $eventData['Image']
                $msg = $ev.Message

                $matchedName = $null
                foreach ($wname in $allWatchedNames) {
                    if ((Test-IOCNameMatch -Text $imageVal -Name $wname) -or (Test-IOCNameMatch -Text $msg -Name $wname)) {
                        $matchedName = $wname; break
                    }
                }
                $matchedNetIoc = $null
                foreach ($n in $NetworkIOCs) { if ($msg -match [regex]::Escape($n.Value)) { $matchedNetIoc = $n.Value; break } }

                if ($ev.Id -eq 3 -and $matchedName) {
                    # This IS the network-communication proof: exact destination IP/port for a watched process
                    $destIp   = $eventData['DestinationIp']
                    $destPort = $eventData['DestinationPort']
                    $Global:EvidenceResults.Add([PSCustomObject]@{
                        IOCName  = $matchedName
                        Artifact = 'Sysmon Event ID 3 (network connection)'
                        Status   = 'NETWORK PROOF OF COMMUNICATION'
                        Detail   = "TimeCreated: $($ev.TimeCreated)  Process: $imageVal  ->  $destIp`:$destPort"
                    })
                } elseif ($matchedName) {
                    $Global:EvidenceResults.Add([PSCustomObject]@{
                        IOCName  = $matchedName
                        Artifact = "Sysmon Event ID $($ev.Id)"
                        Status   = 'DELETED (evidence found)'
                        Detail   = "TimeCreated: $($ev.TimeCreated)  Process: $imageVal"
                    })
                } elseif ($matchedNetIoc) {
                    $Global:EvidenceResults.Add([PSCustomObject]@{
                        IOCName  = $matchedNetIoc
                        Artifact = "Sysmon Event ID $($ev.Id)"
                        Status   = 'NETWORK PROOF OF COMMUNICATION'
                        Detail   = "TimeCreated: $($ev.TimeCreated)  $msg"
                    })
                }
            }
        } else {
            $secEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue -MaxEvents 20000
            foreach ($ev in $secEvents) {
                $msg = $ev.Message
                foreach ($wname in $allWatchedNames) {
                    if (Test-IOCNameMatch -Text $msg -Name $wname) {
                        $Global:EvidenceResults.Add([PSCustomObject]@{
                            IOCName  = $wname
                            Artifact = 'Security 4688 (process creation)'
                            Status   = 'DELETED (evidence found)'
                            Detail   = "TimeCreated: $($ev.TimeCreated)"
                        })
                    }
                }
            }
            if (-not $secEvents) {
                $Global:ScanErrors.Add("[EVENTLOG] No Sysmon operational log and no Security 4688 events available (process-creation auditing likely disabled). Network-communication proof (who these tools talked to) needs Sysmon Event ID 3 specifically - without Sysmon installed, that evidence does not exist on this box regardless of what this script does. Consider installing Sysmon going forward.")
            }
        }
    } catch {
        $Global:ScanErrors.Add("[EVENTLOG] $($_.Exception.Message)")
    }

    # --- PowerShell Script Block Logging (Event ID 4104): often captures the FULL
    # content of a .ps1 even after the file itself is deleted, if it was enabled at
    # the time. Prime candidate for recovering a deleted script's actual content.
    try {
        $psLog = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue
        if ($psLog -and $psLog.RecordCount -gt 0) {
            $sbEvents = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue -MaxEvents 20000 |
                Where-Object { $_.Id -eq 4104 }
            foreach ($ev in $sbEvents) {
                $msg = $ev.Message
                foreach ($wname in $allWatchedNames) {
                    # NOTE: match the FULL name (with extension), anchored - do NOT strip
                    # the extension here. A bare basename like 'cmd' (from 'cmd.bat') is a
                    # substring of Invoke-Command / -Command / cmdlet / Get-Command and
                    # would otherwise light up on nearly every script block ever logged.
                    if (Test-IOCNameMatch -Text $msg -Name $wname) {
                        $Global:EvidenceResults.Add([PSCustomObject]@{
                            IOCName  = $wname
                            Artifact = 'PowerShell Script Block Log (4104)'
                            Status   = 'DELETED (evidence found - content recoverable)'
                            Detail   = "TimeCreated: $($ev.TimeCreated)  ScriptBlockId referenced this name - review full event via: Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' | Where-Object {`$_.Id -eq 4104 -and `$_.RecordId -eq $($ev.RecordId)} | fl"
                        })
                    }
                }
                # Also check for direct IP references inside recovered script content -
                # this is how you find out what a deleted script was actually targeting
                foreach ($n in ($NetworkIOCs + ($InternalHostsOfInterest | ForEach-Object { [PSCustomObject]@{Type='Internal IP'; Value=$_} }))) {
                    if ($msg -match [regex]::Escape($n.Value)) {
                        $Global:EvidenceResults.Add([PSCustomObject]@{
                            IOCName  = $n.Value
                            Artifact = 'PowerShell Script Block Log (4104)'
                            Status   = 'NETWORK PROOF OF COMMUNICATION'
                            Detail   = "TimeCreated: $($ev.TimeCreated)  This IP/host appears inside logged script block content (RecordId $($ev.RecordId))"
                        })
                    }
                }
            }
        } else {
            $Global:ScanErrors.Add("[POWERSHELL-4104] PowerShell Script Block Logging is not enabled/populated on this box. If a malicious .ps1 or similar ran before this scan and this wasn't on, the script content is not recoverable from event logs - only from disk (if not securely wiped) or Recycle Bin.")
        }
    } catch {
        $Global:ScanErrors.Add("[POWERSHELL-4104] $($_.Exception.Message)")
    }

    # --- Amcache / ShimCache: flag location only, don't hand-roll a binary parser ---
    $amcachePath = "$env:WINDIR\AppCompat\Programs\Amcache.hve"
    if (Test-Path -LiteralPath $amcachePath) {
        $Global:EvidenceResults.Add([PSCustomObject]@{
            IOCName  = '(all IOCs)'
            Artifact = 'Amcache.hve (not parsed by this script)'
            Status   = 'MANUAL STEP REQUIRED'
            Detail   = "Found at $amcachePath. Run Eric Zimmerman's AmcacheParser against it: AmcacheParser.exe -f `"$amcachePath`" --csv <outdir>  -- this is the correct tool for this binary registry hive; a hand-rolled parser risks silent misreads."
        })
    }
    $Global:EvidenceResults.Add([PSCustomObject]@{
        IOCName  = '(all IOCs)'
        Artifact = 'ShimCache / AppCompatCache (not parsed by this script)'
        Status   = 'MANUAL STEP REQUIRED'
        Detail   = "Lives in the SYSTEM registry hive (SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache). Export the SYSTEM hive and run Eric Zimmerman's AppCompatCacheParser or KAPE against it for correct parsing."
    })
}

# ======================================================================
#  MAIN
# ======================================================================
try {
    Write-Host ""
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "  IOC Scanner v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "  Target : $ScanPath" -ForegroundColor Cyan
    Write-Host "  Host   : $HostName   User: $RunAsUser" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "Not running elevated. Protected folders, other users' Prefetch/Recycle Bin, and the Security event log will be partially or fully inaccessible - logged as skipped, not fatal."
    }

    if ($FullHashScan -and -not $Force) {
        Write-Warning "FullHashScan hashes EVERY file under $ScanPath. On a full C: drive this can take a long time."
        $confirm = Read-Host "Type YES to proceed with FullHashScan, or press Enter to fall back to fast filename-first matching"
        if ($confirm -ne 'YES') {
            Write-Host "Falling back to fast filename-first matching." -ForegroundColor Cyan
            $FullHashScan = $false
        }
    }

    $OutDir       = Get-WritableOutputDir -Preferred $OutputDir
    $HtmlPath     = Join-Path $OutDir "IOC_Scan_Report_$Timestamp.html"
    $CsvPath      = Join-Path $OutDir "IOC_Matches_$Timestamp.csv"
    $NetCsvPath   = Join-Path $OutDir "IOC_NetworkMatches_$Timestamp.csv"
    $EvCsvPath    = Join-Path $OutDir "IOC_DeletedEvidence_$Timestamp.csv"
    $ErrorLogPath = Join-Path $OutDir "IOC_Scan_Errors_$Timestamp.log"

    Write-Host "Report will be saved to: $OutDir" -ForegroundColor DarkGray
    Write-Host ""

    $startTime      = Get-Date
    $filesScanned   = 0
    $candidatesHashed = 0

    # ---------------- PASS 1: filesystem ----------------
    Get-FilesSafe -RootPath $ScanPath -SkipPrefixes $ExcludePaths | ForEach-Object {
        $filePath = $_
        $filesScanned++

        if ($filesScanned % 5000 -eq 0) {
            $elapsed = (Get-Date) - $startTime
            Write-Progress -Activity "Pass 1/3: Scanning $ScanPath for file IOCs" `
                -Status ("{0:N0} files scanned | {1} matches so far | elapsed {2:hh\:mm\:ss}" -f $filesScanned, $Global:MatchResults.Count, $elapsed)
        }

        $fileName = [System.IO.Path]::GetFileName($filePath)
        $nameKey  = $fileName.ToLowerInvariant()
        $isNameCandidate = $IOCByName.ContainsKey($nameKey)

        if ($isNameCandidate -or $FullHashScan) {
            $candidatesHashed++
            $hashInfo = Get-DualHash -Path $filePath
            if ($null -eq $hashInfo) { return }

            $matchedIOC = $null
            if ($IOCByMD5.ContainsKey($hashInfo.MD5))       { $matchedIOC = $IOCByMD5[$hashInfo.MD5] }
            elseif ($IOCBySHA256.ContainsKey($hashInfo.SHA256)) { $matchedIOC = $IOCBySHA256[$hashInfo.SHA256] }

            $sizeBytes = $null
            try { $sizeBytes = (Get-Item -LiteralPath $filePath -ErrorAction Stop).Length } catch { $sizeBytes = -1 }

            if ($matchedIOC) {
                $result = [PSCustomObject]@{
                    Status = 'CONFIRMED IOC MATCH'; IOCName = $matchedIOC.Name; FilePath = $filePath
                    MD5 = $hashInfo.MD5; SHA256 = $hashInfo.SHA256; SizeBytes = $sizeBytes; DetectedAt = (Get-Date).ToString('u')
                }
                $Global:MatchResults.Add($result)
                $result | Export-Csv -Path $CsvPath -Append -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue
                Write-Host "[!] CONFIRMED MATCH -> $filePath  (known IOC: $($matchedIOC.Name))" -ForegroundColor Red
            }
            elseif ($isNameCandidate) {
                $result = [PSCustomObject]@{
                    Status = 'SUSPICIOUS NAME MATCH (hash differs)'; IOCName = $fileName; FilePath = $filePath
                    MD5 = $hashInfo.MD5; SHA256 = $hashInfo.SHA256; SizeBytes = $sizeBytes; DetectedAt = (Get-Date).ToString('u')
                }
                $Global:MatchResults.Add($result)
                $result | Export-Csv -Path $CsvPath -Append -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue
                Write-Host "[?] Name matches a known IOC but hash differs -> $filePath" -ForegroundColor Yellow
            }
        }
    }
    Write-Progress -Activity "Pass 1/3: Scanning $ScanPath for file IOCs" -Completed

    # ---------------- PASS 2: network IOCs ----------------
    if (-not $SkipNetworkIOCs) {
        Write-Host "Pass 2/3: Checking DNS cache / hosts file / browser history for network IOCs..." -ForegroundColor Cyan
        Invoke-NetworkIOCScan
        if ($Global:NetworkMatches.Count -gt 0) {
            $Global:NetworkMatches | Export-Csv -Path $NetCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "Pass 2/3: Skipped (-SkipNetworkIOCs)" -ForegroundColor DarkGray
    }

    # ---------------- PASS 3: deleted-evidence ----------------
    if (-not $SkipEvidencePass) {
        Write-Host "Pass 3/3: Checking Prefetch / Recycle Bin / Event Logs for evidence of deleted IOCs..." -ForegroundColor Cyan
        Invoke-EvidencePass
        if ($Global:EvidenceResults.Count -gt 0) {
            $Global:EvidenceResults | Export-Csv -Path $EvCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "Pass 3/3: Skipped (-SkipEvidencePass)" -ForegroundColor DarkGray
    }

    $endTime = Get-Date
    $duration = $endTime - $startTime

    # [HTML report generation, console summary, and exit-code logic omitted here
    #  for article length — see the full script in the repo linked below.]

} catch {
    Write-Warning "Unexpected error - scan halted early, partial report may still be saved: $($_.Exception.Message)"
    $Global:ExitCode = 99
} finally {
    exit $Global:ExitCode
}
