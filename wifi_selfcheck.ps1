<#
.SYNOPSIS
  WiFi Capture Reality Check - Windows self-check. Read-only. No admin needed.

.DESCRIPTION
  Checks THIS PC only and reports:
    1. who is running it, and whether this window is elevated (admin)
    2. your wireless adapters, their drivers, and whether the driver says it supports
       "Network monitor mode" (Windows' name for 802.11 monitor mode)
    3. whether a packet-capture driver (Npcap, or the old WinPcap) is installed, whether
       non-admin programs may use it, and whether raw 802.11 capture is switched on
    4. any custom security descriptor (SDDL) set on the adapter device, in plain English

  It changes nothing. It only reads adapter properties, registry values and the output of
  'netsh wlan show wirelesscapabilities'. It never switches modes, scans, captures or transmits.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\wifi_selfcheck.ps1

  "-ExecutionPolicy Bypass" applies to this one run only. Read the script before you run it.
  Exit code: 0 = nothing flagged, 3 = at least one [FLAG] line.
  MIT licence. https://github.com/warboy176/wifi-capture-reality-check
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'SilentlyContinue'
$script:Flags = 0
function Say  ($t) { Write-Output $t }
function Ok   ($t) { Write-Output "  [ok]   $t" }
function Info ($t) { Write-Output "  [info] $t" }
function Flag ($t) { Write-Output "  [FLAG] $t"; $script:Flags++ }

Say "WiFi Capture Reality Check -- Windows self-check (read-only)"
Say ""

# ------------------------------------------------------------------ 1. who is running this
Say "== 1. Who is running this"
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# S-1-5-32-544 = the local Administrators group. SIDs are not translated, so this works in any language.
$isAdminMember = [bool]((whoami /groups /fo csv 2>$null) -match 'S-1-5-32-544')
Info "user: $($me.Name)"
if ($elevated) {
    Info "This window is ELEVATED (running as administrator). Administrators can always install capture"
    Info "drivers and switch adapter modes. Run it from a normal window too, for your everyday view."
} elseif ($isAdminMember) {
    Info "Not elevated right now, but this account is an administrator (it can elevate through UAC)."
} else {
    Ok "Standard user, not elevated."
}

# ------------------------------------------------------------------ 2. wireless adapters
Say ""
Say "== 2. Wireless adapters"
# NdisPhysicalMedium 9 = native 802.11
$wifi = @(Get-NetAdapter | Where-Object { $_.NdisPhysicalMedium -eq 9 -or $_.PhysicalMediaType -match '802\.11' })
if ($wifi.Count -eq 0) { Info "No wireless adapters found. Nothing radio-related to check on this PC." }

# 'netsh wlan show wirelesscapabilities' lists, per interface, "Network monitor mode : Supported/Not supported"
$caps = @{}
$cur = $null
foreach ($line in (netsh wlan show wirelesscapabilities 2>$null)) {
    if ($line -match '^\s*Interface name\s*:\s*(.+?)\s*$') { $cur = $Matches[1]; $caps[$cur] = @{}; continue }
    if ($cur -and $line -match '^\s*(Network monitor mode|Promiscuous Mode)\s*:\s*(.+?)\s*$') {
        $caps[$cur][$Matches[1]] = $Matches[2]
    }
}

$monitorSummary = @()
foreach ($a in $wifi) {
    Info ("{0}: {1}" -f $a.Name, $a.InterfaceDescription)
    Info ("   status {0}, driver {1} {2} ({3})" -f $a.Status, $a.DriverProvider, $a.DriverVersion, $a.DriverDate)
    $mon = 'unknown'
    if ($caps.ContainsKey($a.Name) -and $caps[$a.Name].ContainsKey('Network monitor mode')) {
        $mon = $caps[$a.Name]['Network monitor mode']
    }
    if ($mon -match '^Supported') {
        Info "   Network monitor mode: SUPPORTED by this driver (switching to it still needs an administrator)"
    } elseif ($mon -match 'Not supported') {
        Info "   Network monitor mode: not supported by this driver"
    } else {
        Info "   Network monitor mode: unknown (this Windows version or language did not report it)"
    }
    if ($caps.ContainsKey($a.Name) -and $caps[$a.Name].ContainsKey('Promiscuous Mode')) {
        Info ("   Promiscuous mode: {0}" -f $caps[$a.Name]['Promiscuous Mode'])
    }
    $monitorSummary += ("{0}: monitor mode {1}" -f $a.Name, $mon)
}

# ------------------------------------------------------------------ 3. capture drivers
Say ""
Say "== 3. Packet-capture drivers (what lets programs like Wireshark capture)"
$nonAdminCapture = 'no'
$npcap = Get-Service -Name npcap
if ($npcap) {
    $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters'
    Info "Npcap is installed (driver state: $($npcap.Status))."
    if ($p -and $p.AdminOnly -eq 1) {
        Ok "Npcap is restricted to administrators (AdminOnly=1). Non-admin programs cannot capture."
    } else {
        Info "Npcap is NOT restricted to administrators (AdminOnly is not 1, the installer's default)."
        Info "   Any program, run by any local user, can capture on the adapters Npcap is bound to."
        Info "   That is a documented install option, not a hack. To close it, reinstall Npcap with"
        Info "   'Restrict Npcap driver's access to Administrators only' ticked."
        $nonAdminCapture = 'yes (Npcap is not admin-only)'
    }
    if ($p -and $p.Dot11Support -eq 1) {
        Info "Raw 802.11 support is ON (Dot11Support=1): with an adapter in monitor mode, Npcap hands"
        Info "   programs raw WiFi frames. Putting the adapter into monitor mode still needs an administrator."
    } else {
        Ok "Raw 802.11 support is off (Dot11Support is not 1)."
    }
} else {
    Ok "Npcap is not installed."
}
$winpcap = (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst') -or
           (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst')
if ($winpcap) {
    Flag "WinPcap is installed. It is no longer maintained and has no 'administrators only' option. Replace it with Npcap."
    $nonAdminCapture = 'likely (WinPcap installed)'
}

# ------------------------------------------------------------------ 4. device security
Say ""
Say "== 4. Security settings on the adapter devices"
$who = @{ WD = 'Everyone'; AU = 'Authenticated Users'; BU = 'Users'; IU = 'Interactive users'; BG = 'Guests';
          AN = 'Anonymous'; BA = 'Administrators'; SY = 'SYSTEM'; RC = 'Restricted code'; LS = 'Local Service';
          NS = 'Network Service'; WR = 'Write-restricted code'; AC = 'App containers' }
$broad = @('WD', 'AU', 'BU', 'IU', 'BG', 'AN', 'AC')

function Get-AceList ($sddl) {
    # Turns "(A;;GA;;;SY)(A;;GR;;;WD)" into readable rows. A = allow, D = deny.
    foreach ($m in [regex]::Matches($sddl, '\((A|D);[^;]*;([^;]*);[^;]*;[^;]*;([^)]*)\)')) {
        $rights = $m.Groups[2].Value
        $canWrite = $false
        if ($rights -match '^0x([0-9a-fA-F]+)$') {
            $mask = [Convert]::ToInt64($Matches[1], 16)
            # FILE_WRITE_DATA, FILE_APPEND_DATA, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
            $canWrite = ($mask -band (0x2 -bor 0x4 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)) -ne 0
        } else {
            foreach ($tok in ($rights -split '(..)' | Where-Object { $_ })) {
                if ($tok -in @('GA', 'GW', 'FA', 'FW', 'WD', 'WO')) { $canWrite = $true }
            }
        }
        $sid = $m.Groups[3].Value
        $name = if ($who.ContainsKey($sid)) { $who[$sid] } else { $sid }
        [pscustomobject]@{ Allow = ($m.Groups[1].Value -eq 'A'); Sid = $sid; Who = $name; Rights = $rights; Write = $canWrite }
    }
}

$customSddl = 0
foreach ($a in $wifi) {
    $sds = (Get-PnpDeviceProperty -InstanceId $a.PnPDeviceID -KeyName 'DEVPKEY_Device_SecuritySDS').Data
    if (-not $sds) {
        Ok "$($a.Name): no custom security descriptor on the device. The driver's and Windows' defaults apply."
        continue
    }
    $customSddl++
    Info "$($a.Name): custom security descriptor: $sds"
    foreach ($ace in (Get-AceList $sds)) {
        $verb = if ($ace.Allow) { 'allowed' } else { 'DENIED' }
        $what = if ($ace.Write) { 'read AND write' } else { 'read/other' }
        Info ("   {0} {1}: {2} (rights {3})" -f $ace.Who, $verb, $what, $ace.Rights)
        if ($ace.Allow -and $ace.Write -and ($broad -contains $ace.Sid)) {
            Flag "$($a.Name): '$($ace.Who)' may open this device for WRITING. If that came from the vendor's driver package, it is a driver bug worth reporting to the vendor."
        }
    }
}

# ------------------------------------------------------------------ summary
Say ""
Say "== Summary"
Say ("  Wireless adapters: {0}" -f $wifi.Count)
foreach ($s in $monitorSummary) { Say "    - $s" }
Say "  This window is elevated: $elevated"
Say "  Non-admin packet capture possible on this PC: $nonAdminCapture"
Say "  Adapters with a custom security descriptor: $customSddl"
Say "  FLAGS: $($script:Flags)"
Say ""
Say "What this means:"
Say "  - 'Network monitor mode: SUPPORTED' is a normal, documented driver feature. Using it needs an"
Say "    administrator to switch the adapter over. Nothing here 'unlocks' anything."
Say "  - Non-admin capture is possible only if a capture driver was installed that way (Npcap without"
Say "    'admin only', or the old WinPcap). That is an install choice, not a hack."
Say "  - Opening a device is not the same as capturing from it. What a handle can do depends on what"
Say "    the driver accepts. A [FLAG] is worth fixing and reporting to the vendor: a bug report, not magic."
Say "  - Only capture on networks and devices you own or are allowed to test."
if ($script:Flags -gt 0) { exit 3 } else { exit 0 }
