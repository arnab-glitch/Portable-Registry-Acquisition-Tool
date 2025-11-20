<#
RegEx v1 — RegTrace upgraded (Full Forensic Mode)
#>

# ---------- Compatibility & Elevation ----------
function Assert-PowerShellVersion {
    param([int]$min=3)
    if ($PSVersionTable.PSVersion -eq $null) { Write-Error "Cannot determine PSVersion"; exit 1 }
    if ($PSVersionTable.PSVersion.Major -lt $min) { Write-Error "PowerShell v$min+ required"; exit 1 }
}
Assert-PowerShellVersion -min 3

function Ensure-Elevated {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        if ($PSCommandPath) {
            Write-Host "Not elevated. Relaunching..."
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = (Get-Process -Id $PID).Path
            $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            $psi.Verb = 'runas'
            [System.Diagnostics.Process]::Start($psi) | Out-Null
            exit 0
        } else {
            Throw "Script must be run elevated."
        }
    }
}
Ensure-Elevated

# ---------- Utilities ----------
function Get-SHA256 {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try { return (Get-FileHash -Path $Path -Algorithm SHA256).Hash } catch {}
    # fallback .NET
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = $sha.ComputeHash($stream)
        $stream.Close()
        return ([BitConverter]::ToString($bytes)).Replace("-","")
    } catch { return $null }
}

function Join-System32 {
    param([string]$rel)
    $windir = $env:windir
    if ($env:PROCESSOR_ARCHITECTURE -eq 'x86' -and [Environment]::Is64BitOperatingSystem) {
        $sysnative = Join-Path $windir 'sysnative'
        if (Test-Path $sysnative) { return Join-Path $sysnative $rel }
    }
    return Join-Path (Join-Path $windir 'System32') $rel
}

function Write-Log {
    param([string]$m)
    if (-not $Global:LogPath) { $Global:LogPath = "regex_log.txt" }
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    $line = "$ts`t$m"
    Add-Content -Path $Global:LogPath -Value $line -Encoding UTF8
    Write-Host $line
}

function Safe-Copy {
    param([string]$src, [string]$dst)
    try {
        if (-not (Test-Path $src)) {
            Write-Log "MISSING: $src"
            return @{ok=$false; note="missing"; source=$src}
        }
        $dir = Split-Path $dst -Parent
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        Copy-Item -Path $src -Destination $dst -Force -ErrorAction Stop
        $sha = Get-SHA256 $dst
        $size = (Get-Item $dst).Length
        return @{ok=$true; dest=$dst; sha256=$sha; size=$size}
    } catch {
        Write-Log "ERROR copying $src -> $dst : $($_.Exception.Message)"
        return @{ok=$false; error=$_.Exception.Message}
    }
}

function Run-RegSave {
    param([string]$Key, [string]$OutFile)
    try {
        $dir = Split-Path $OutFile -Parent
        if (-not (Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }
        Write-Log "REG SAVE $Key"
        $cmd = "reg.exe save `"$Key`" `"$OutFile`" /y"
        cmd.exe /c $cmd | Out-Null
        if ($LASTEXITCODE -eq 0 -and (Test-Path $OutFile)) {
            return @{
                ok=$true;
                dest=$OutFile;
                sha256=(Get-SHA256 $OutFile);
                size=(Get-Item $OutFile).Length
            }
        }
        return @{ok=$false; error="reg save failed"}
    } catch {
        return @{ok=$false; error=$_.Exception.Message}
    }
}

function Run-RegExport {
    param([string]$Key, [string]$OutFile)
    try {
        $dir = Split-Path $OutFile -Parent
        if (-not (Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }
        Write-Log "REG EXPORT $Key"
        $cmd = "reg.exe export `"$Key`" `"$OutFile`" /y"
        cmd.exe /c $cmd | Out-Null
        if ($LASTEXITCODE -eq 0 -and (Test-Path $OutFile)) {
            return @{
                ok=$true;
                dest=$OutFile;
                sha256=(Get-SHA256 $OutFile)
            }
        }
        return @{ok=$false; error="reg export failed"}
    } catch {
        return @{ok=$false; error=$_.Exception.Message}
    }
}

function Get-FreeDriveLetter {
    $letters = 'Z','Y','X','W','V','U','T','S','R','Q','P'
    $used = (Get-PSDrive -PSProvider FileSystem).Name
    foreach ($l in $letters) {
        if ($used -notcontains $l) { return "${l}:" }
    }
    return $null
}
# ---------- USB history exporter ----------
function Export-USB-History {
    param([string]$OutCSV, [string]$EvidenceRoot)
    $rows = @()

    try {
        $key = "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        # Query top-level keys under USBSTOR
        $vendors = & reg query "$key" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "No USBSTOR entries or access denied."
        } else {
            # reg query prints key paths; filter lines starting with HKEY
            foreach ($line in $vendors) {
                if ($line -and $line.Trim().StartsWith("HKEY_LOCAL_MACHINE")) {
                    $vendorKey = $line.Trim()
                    # enumerate instances under vendorKey
                    $instances = & reg query "$vendorKey" 2>&1
                    foreach ($instLine in $instances) {
                        if ($instLine -and $instLine.Trim().StartsWith("HKEY_LOCAL_MACHINE")) {
                            $instanceKey = $instLine.Trim()
                            # attempt to read FriendlyName and ParentIdPrefix
                            $friendly = & reg query "`"$instanceKey`"" /v FriendlyName 2>&1
                            $fname = ""
                            foreach ($fl in $friendly) {
                                if ($fl -match "FriendlyName") {
                                    # line like:    FriendlyName    REG_SZ    SanDisk Cruzer Blade
                                    $parts = $fl -split "\s{2,}"
                                    if ($parts.Length -ge 3) { $fname = $parts[2].Trim() } else { $fname = $fl.Trim() }
                                }
                            }
                            $parent = ""
                            $pp = & reg query "`"$instanceKey`"" /v ParentIdPrefix 2>&1
                            foreach ($pl in $pp) {
                                if ($pl -match "ParentIdPrefix") {
                                    $parts = $pl -split "\s{2,}"
                                    if ($parts.Length -ge 3) { $parent = $parts[2].Trim() } else { $parent = $pl.Trim() }
                                }
                            }
                            $rows += [PSCustomObject]@{ vendor_key = $vendorKey; instance = $instanceKey; friendly = $fname; parent = $parent }
                        }
                    }
                }
            }
        }
    } catch {
        Write-Log "USB parse exception: $_"
    }

    # MountedDevices fallback marker (we add as presence indicator)
    try {
        $md = (& reg query "HKLM\SYSTEM\MountedDevices" 2>&1) -join "`n"
        if ($md) {
            $rows += [PSCustomObject]@{ vendor_key = "MountedDevices"; instance = "MountedDevices"; friendly = "(binary data)"; parent = "" }
        }
    } catch { }

    # Ensure output dir and write CSV
    try {
        $outDir = Split-Path $OutCSV -Parent
        if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
        if ($rows.Count -gt 0) {
            $rows | Export-Csv -Path $OutCSV -NoTypeInformation -Force -Encoding UTF8
            Write-Log "USB history exported to $OutCSV"
        } else {
            # create empty CSV with headers
            $headers = @("vendor_key","instance","friendly","parent")
            $headers -join "," | Out-File -FilePath $OutCSV -Encoding UTF8
            Write-Log "USB history empty, wrote header CSV $OutCSV"
        }
    } catch {
        Write-Log "Failed to write USB CSV: $_"
    }

    return $OutCSV
}

# ---------- START COLLECTION ----------
try {
    Write-Host "=== RegEx v1 acquisition START ==="

    # Operator inputs
    $Operator = Read-Host "Operator name (watermark)"
    $CaseID = Read-Host "Case ID"
    $EvidenceTarget = Read-Host "Evidence target (e.g. E:\ )"
    if ([string]::IsNullOrWhiteSpace($EvidenceTarget)) { Throw "Evidence target empty." }
    $ePath = $EvidenceTarget.Trim()
    if ($ePath.Length -eq 2 -and $ePath[1] -eq ':') { $ePath += "\" }
    if ($ePath.ToUpper().StartsWith("C:\") -or $ePath.ToUpper() -eq "C:") { Throw "Evidence path on C: is forbidden." }

    # Setup folders
    $EvidenceRoot = Join-Path -Path $ePath -ChildPath ("RegEx_Evidence\{0}" -f $CaseID)
    $ExtractDir = Join-Path -Path $EvidenceRoot -ChildPath "Extracted_Hives"
    $EventDir = Join-Path -Path $EvidenceRoot -ChildPath "Event_Logs"
    $PrefetchDir = Join-Path -Path $EvidenceRoot -ChildPath "Prefetch"
    $AmcacheDir = Join-Path -Path $EvidenceRoot -ChildPath "Amcache"
    $RegExportsDir = Join-Path -Path $EvidenceRoot -ChildPath "Registry_Exports"
    $UsbCsv = Join-Path -Path $EvidenceRoot -ChildPath "usb_history.csv"

    New-Item -Path $ExtractDir -ItemType Directory -Force | Out-Null
    New-Item -Path $EventDir -ItemType Directory -Force | Out-Null
    New-Item -Path $PrefetchDir -ItemType Directory -Force | Out-Null
    New-Item -Path $AmcacheDir -ItemType Directory -Force | Out-Null
    New-Item -Path $RegExportsDir -ItemType Directory -Force | Out-Null

    $Global:LogPath = Join-Path -Path $EvidenceRoot -ChildPath "regex_log.txt"
    $manifestPath = Join-Path -Path $EvidenceRoot -ChildPath "manifest.json"
 

    Write-Log "Evidence root: $EvidenceRoot"
    Write-Log "Operator: $Operator ; CaseID: $CaseID"

 

    # VSS attempt
    $ExposeDrive = Get-FreeDriveLetter
    $diskshadowExe = Join-System32 'diskshadow.exe'
    $shadowGUID = $null
    $shadowSucceeded = $false

    if ($ExposeDrive -and (Test-Path $diskshadowExe)) {
        $tempDS = "$env:TEMP\regex_diskshadow.txt"
        @("SET CONTEXT PERSISTENT","ADD VOLUME C: ALIAS SystemVol","CREATE","EXPOSE %SystemVol% $ExposeDrive") | Out-File -FilePath $tempDS -Encoding ASCII
        Write-Log "Attempting diskshadow (VSS) create/expose..."
        try {
            $out = & $diskshadowExe /s $tempDS 2>&1
            $txt = ($out -join "`n")
            Write-Log "diskshadow output:`n$txt"
            $matches = [regex]::Matches($txt, '\{[0-9a-fA-F\-]{36}\}')
            if ($matches.Count -gt 0) {
                $shadowGUID = $matches[0].Value
                $shadowSucceeded = $true
                Write-Log "Captured GUID $shadowGUID"
            } else {
                Write-Log "diskshadow created no GUID."
            }
        } catch {
            Write-Log "diskshadow error: $_"
        }
    } else {
        Write-Log "diskshadow not available or no free drive letter; skipping VSS attempt."
    }

    $manifestItems = @()
    # ---------- COLLECTION PHASE ----------

    if ($shadowSucceeded -and $ExposeDrive -and (Test-Path ("$ExposeDrive\"))) {

        Write-Log "VSS mode: collecting artifacts from snapshot at $ExposeDrive"

        # Core system hives
        $core = @{
            "SYSTEM"   = "Windows\System32\config\SYSTEM";
            "SOFTWARE" = "Windows\System32\config\SOFTWARE";
            "SAM"      = "Windows\System32\config\SAM";
            "SECURITY" = "Windows\System32\config\SECURITY";
            "DEFAULT"  = "Windows\System32\config\DEFAULT"
        }

        foreach ($name in $core.Keys) {
            $src = Join-Path $ExposeDrive $core[$name]
            $dst = Join-Path $ExtractDir "$name.hive"
            $r = Safe-Copy -src $src -dst $dst
            $manifestItems += @{
                artifact = $name
                method   = "vss"
                source   = $src
                dest     = $dst
                ok       = $r.ok
                sha256   = $r.sha256
                size     = $r.size
            }
        }

        # Event logs
        $evtxPath = Join-Path $ExposeDrive "Windows\System32\winevt\Logs"
        if (Test-Path $evtxPath) {
            $evtxList = Get-ChildItem $evtxPath -Filter *.evtx -File -ErrorAction SilentlyContinue
            foreach ($x in $evtxList) {
                $dst = Join-Path $EventDir $x.Name
                $r = Safe-Copy -src $x.FullName -dst $dst
                $manifestItems += @{
                    artifact = "evtx"
                    source   = $x.FullName
                    dest     = $dst
                    ok       = $r.ok
                    sha256   = $r.sha256
                    size     = $r.size
                }
            }
        }

        # Prefetch
        $pf = Join-Path $ExposeDrive "Windows\Prefetch"
        if (Test-Path $pf) {
            $pfList = Get-ChildItem $pf -Filter *.pf -File -ErrorAction SilentlyContinue
            foreach ($p in $pfList) {
                $dst = Join-Path $PrefetchDir $p.Name
                $r = Safe-Copy -src $p.FullName -dst $dst
                $manifestItems += @{
                    artifact = "prefetch"
                    source   = $p.FullName
                    dest     = $dst
                    ok       = $r.ok
                    sha256   = $r.sha256
                    size     = $r.size
                }
            }
        }

        # Amcache (best-effort)
        $amSrc = Join-Path $ExposeDrive "Windows\AppCompat\Programs\Amcache.hve"
        $amDst = Join-Path $AmcacheDir "Amcache.hve"
        $r = Safe-Copy -src $amSrc -dst $amDst
        $manifestItems += @{
            artifact = "Amcache"
            source   = $amSrc
            dest     = $amDst
            ok       = $r.ok
            sha256   = $r.sha256
            size     = $r.size
        }

    } else {

        # ---------- FALLBACK MODE ----------
        Write-Log "Fallback mode: full forensic exports (reg save + reg export + wevtutil + best-effort copies)"

        # Core HKLM hives via reg save
        $coreMap = @{
            "SYSTEM"   = "HKLM\SYSTEM"
            "SOFTWARE" = "HKLM\SOFTWARE"
            "SAM"      = "HKLM\SAM"
            "SECURITY" = "HKLM\SECURITY"
            "DEFAULT"  = "HKLM\DEFAULT"
        }

        foreach ($k in $coreMap.Keys) {
            $out = Join-Path $ExtractDir "$k.hive"
            $r = Run-RegSave -Key $coreMap[$k] -OutFile $out
            $manifestItems += @{
                artifact = $k
                method   = "reg_save"
                dest     = $out
                ok       = $r.ok
                sha256   = $r.sha256
                size     = $r.size
                error    = $r.error
            }
        }

        # HKU hives via reg save
        try {
            $hkus = Get-ChildItem HKU: -ErrorAction SilentlyContinue
            foreach ($h in $hkus) {
                $sid = $h.PSChildName
                if ($sid -match '^\d+-\d+-\d+-\d+-\d+$') {
                    $out = Join-Path $ExtractDir "HKU_$sid.hive"
                    $r = Run-RegSave -Key "HKU\$sid" -OutFile $out
                    $manifestItems += @{
                        artifact = "HKU"
                        sid      = $sid
                        method   = "reg_save"
                        dest     = $out
                        ok       = $r.ok
                        sha256   = $r.sha256
                        size     = $r.size
                    }
                }
            }
        } catch {
            Write-Log "HKU export failed: $_"
        }

        # Important registry exports
        $exports = @(
            @{key="HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"; out="USBSTOR.reg"},
            @{key="HKLM\SYSTEM\CurrentControlSet\Enum\USB";     out="USB.reg"},
            @{key="HKLM\SYSTEM\MountedDevices";                 out="MountedDevices.reg"}
        )

        foreach ($e in $exports) {
            $outf = Join-Path $RegExportsDir $e.out
            $r = Run-RegExport -Key $e.key -OutFile $outf
            $manifestItems += @{
                artifact = "reg_export"
                key      = $e.key
                dest     = $outf
                ok       = $r.ok
                sha256   = $r.sha256
                error    = $r.error
            }
        }

        # User NTUSER & UsrClass (best-effort)
        $usersRoot = "C:\Users"
        if (Test-Path $usersRoot) {
            $usrList = Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue
            foreach ($u in $usrList) {
                $uname = $u.Name
                $profile = $u.FullName
                $outDir = Join-Path $ExtractDir $uname
                if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }

                # NTUSER.DAT
                $nt = Join-Path $profile "NTUSER.DAT"
                $ntdst = Join-Path $outDir "NTUSER.DAT"
                $ntRes = Safe-Copy -src $nt -dst $ntdst
                $manifestItems += @{
                    artifact = "NTUSER.DAT"
                    user     = $uname
                    source   = $nt
                    dest     = $ntdst
                    ok       = $ntRes.ok
                    sha256   = $ntRes.sha256
                }

                # UsrClass.dat
                $uc = Join-Path $profile "AppData\Local\Microsoft\Windows\UsrClass.dat"
                $ucdst = Join-Path $outDir "UsrClass.dat"
                $ucRes = Safe-Copy -src $uc -dst $ucdst
                $manifestItems += @{
                    artifact = "UsrClass.dat"
                    user     = $uname
                    source   = $uc
                    dest     = $ucdst
                    ok       = $ucRes.ok
                    sha256   = $ucRes.sha256
                }
            }
        }

        # Event logs
        $channels = @("System","Application","Security")
        foreach ($ch in $channels) {
            $outf = Join-Path $EventDir "$ch.evtx"
            Write-Log "Exporting channel $ch -> $outf"
            try {
                $res = wevtutil epl $ch $outf 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $outf)) {
                    $manifestItems += @{
                        artifact = "evtx"
                        channel  = $ch
                        dest     = $outf
                        ok       = $true
                        sha256   = (Get-SHA256 $outf)
                    }
                } else {
                    $manifestItems += @{
                        artifact = "evtx"
                        channel  = $ch
                        dest     = $outf
                        ok       = $false
                        error    = ($res -join "`n")
                    }
                }
            } catch {
                Write-Log "wevtutil error: $_"
            }
        }

        # Prefetch (best-effort)
        $pf = "C:\Windows\Prefetch"
        if (Test-Path $pf) {
            $pfList = Get-ChildItem $pf -Filter *.pf -File -ErrorAction SilentlyContinue
            foreach ($p in $pfList) {
                $dst = Join-Path $PrefetchDir $p.Name
                $r = Safe-Copy -src $p.FullName -dst $dst
                $manifestItems += @{
                    artifact = "prefetch"
                    source   = $p.FullName
                    dest     = $dst
                    ok       = $r.ok
                    sha256   = $r.sha256
                }
            }
        }

        # Amcache
        $am = "C:\Windows\AppCompat\Programs\Amcache.hve"
        $amdst = Join-Path $AmcacheDir "Amcache.hve"
        $r = Safe-Copy -src $am -dst $amdst
        $manifestItems += @{
            artifact = "Amcache"
            source   = $am
            dest     = $amdst
            ok       = $r.ok
            sha256   = $r.sha256
        }
    }

    # ----- USB History CSV -----
    $usbCsvOut = Export-USB-History -OutCSV $UsbCsv -EvidenceRoot $EvidenceRoot
    $manifestItems += @{
        artifact = "usb_history_csv"
        dest     = $usbCsvOut
        ok       = (Test-Path $usbCsvOut)
    }

    
    # Determine acquisition method safely
    $acqMethod = "fallback"
    if ($shadowSucceeded) {
        $acqMethod = "vss"
    }

    # Build manifest object
    $manifestObj = @{
        tool          = "RegEx v1"
        version       = "1.0"
        operator      = $Operator
        case_id       = $CaseID
        collected_at  = (Get-Date).ToString("o")
        method        = $acqMethod
        items         = $manifestItems
    }


    # Write manifest
    $manifestObj | ConvertTo-Json -Depth 20 | Out-File $manifestPath -Encoding UTF8

    # Compute manifest hash & rewrite
    $mh = Get-SHA256 $manifestPath
    $manifestObj.manifest_hash = $mh
    $manifestObj | ConvertTo-Json -Depth 20 | Out-File $manifestPath -Encoding UTF8
    Write-Log "Manifest written (hash=$mh)"

    # ----- VSS Cleanup -----
    if ($shadowSucceeded -and $shadowGUID) {
        try {
            Write-Log "Cleaning VSS snapshot $shadowGUID"
            $cleanupFile = "$env:TEMP\regex_cleanup.txt"
            @("SET CONTEXT PERSISTENT","DELETE SHADOWS ID $shadowGUID") | Out-File $cleanupFile -Encoding ASCII
            $cOut = & $diskshadowExe /s $cleanupFile 2>&1
            Write-Log ("Cleanup:`n" + ($cOut -join "`n"))
        } catch {
            Write-Log "Cleanup failed: $_"
        }
    }

    # ---------- Operation Summary ----------
    $summaryPath = Join-Path $EvidenceRoot "operation_summary.txt"
    @(
        "Tool: RegEx v1"
        "Operator: $Operator"
        "CaseID: $CaseID"
        "Mode: $($manifestObj.method)"
        "ManifestHash: $mh"
        "CompletedAt: $(Get-Date -Format o)"
    ) | Out-File $summaryPath -Encoding UTF8

    Write-Log "Summary written to $summaryPath"
    Write-Log "=== RegEx v1 acquisition COMPLETE ==="

} catch {
    Write-Log "FATAL ERROR: $_"
    Write-Host "FATAL ERROR: $_" -ForegroundColor Red
    exit 1
} finally {
    Write-Log "Exiting."
}
