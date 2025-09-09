# Bob-the-SystemRepair, simple but pretty good powershell script for a full system scan and repair :3
# IMPORTANT: Although everything from the powershell output that is displayed in the PowerShell console should be saved in BobScans.log, results of stuff like Defender full scan and MRT are not in this log file :( .. 
# Script is not signed so this is required: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass


$logPath = "$env:USERPROFILE\Desktop\BobScans.log"
Start-Transcript -Path $logPath -Force | Out-Null

# Make sure bob has Administrator access, as otherwise some scans will fail..
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")){
Write-Host "[!] ERROR: This script requires to be run as an Administrator due to the deep level scan it does. [!]" -ForegroundColor DarkRed    
pause
exit
}


Write-Host "Bob-the-SystemRepair Scan" -ForegroundColor Green
Write-Host "IMPORTANT:" -ForegroundColor Green
Write-Host "! Anything in RED is worth investigating! Do not ignore them by default THEY CAN BE BAD, but also don't blindly believe them!" -ForegroundColor Green
Write-Host "Results are also saved to: $logPath" -ForegroundColor DarkMagenta
Write-Host "DO NOT INTERRUPT THE SCAN, DOING SO MAY CAUSE PROBLEMS!" -ForegroundColor Yellow

# Helper func to make it all easier
function Get-RegistryValueSafe {
    param ($Path, $Name = $null)
    try {
        if ($Name) { Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop }
        else { Get-ItemProperty -Path $Path -ErrorAction Stop }
    } catch { return $null }
}

# Startup Folder checks!!!
Write-Host "`n[Startup Folders]" -ForegroundColor Cyan
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
#Lazy way but it works
$startupFound = $false
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem $folder | ForEach-Object {
            Write-Host $_.FullName -ForegroundColor Red
            $startupFound = $true
        }
    }
}
if (-not $startupFound) { Write-Host "No startup folder files found." -ForegroundColor Green }

# Registry Run Keys 
Write-Host "`n[Registry Run/RunOnce Keys]" -ForegroundColor Cyan
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$runFound = $false
foreach ($key in $runKeys) {
    $props = Get-RegistryValueSafe $key
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object {
            Write-Host "$($key)\$($_.Name): $($_.Value)" -ForegroundColor Red
            $runFound = $true
        }
    }
}
if (-not $runFound) { Write-Host "No Run or RunOnce entries found." -ForegroundColor Green }

# Scheduled Tasks 
Write-Host "`n[Scheduled Tasks]" -ForegroundColor Cyan
$tasks = schtasks /query /fo CSV | ConvertFrom-Csv | Where-Object { $_."TaskName" -notlike "*Microsoft*" }
if ($tasks) { $tasks | ForEach-Object { Write-Host $_.TaskName -ForegroundColor Red } }
else { Write-Host "No non-Microsoft scheduled tasks found this time!" -ForegroundColor Green }

# WMI Consumers 
Write-Host "`n[WMI Event Consumers]" -ForegroundColor Cyan
$wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
if ($wmiConsumers) { $wmiConsumers | ForEach-Object { Write-Host $_.Name -ForegroundColor Red } }
else { Write-Host "No WMI event consumers found." -ForegroundColor Green }

# Services 
Write-Host "`n[Services]" -ForegroundColor Cyan
$services = Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch "Windows|Program Files|System32|SysWOW64" }
if ($services) {
    $services | ForEach-Object { Write-Host "$($_.Name): $($_.PathName)" -ForegroundColor Yellow }
    Write-Host "! Review manually may be vendor services so ye." -ForegroundColor Yellow
}
else { Write-Host "No unusual services found." -ForegroundColor Green }

# Winlogon Keys 
Write-Host "`n[Winlogon Keys]" -ForegroundColor Cyan
$winlogonKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
)
foreach ($key in $winlogonKeys) {
    $props = Get-RegistryValueSafe $key
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object {
            Write-Host "$($key)\$($_.Name): $($_.Value)" -ForegroundColor Red
        }
    } else {
        Write-Host "No non-standard Winlogon entries found in $key." -ForegroundColor Green
    }
}

# IFEO Hijacks, rare but sometimes we get hits
Write-Host "`n[IFEO Debugger Hijacks!]" -ForegroundColor Cyan
$ifeoFound = $false
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | ForEach-Object {
    $debugger = Get-RegistryValueSafe $_.PSPath "Debugger"
    if ($debugger) { Write-Host "$($_.PSPath): $($debugger.Debugger)" -ForegroundColor Red; $ifeoFound = $true }
}
if (-not $ifeoFound) { Write-Host "No IFEO debugger entries found." -ForegroundColor Green }

# AppInit DLLs quickly
Write-Host "`n[AppInit_DLLs]" -ForegroundColor Cyan
$appInit = Get-RegistryValueSafe "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" "AppInit_DLLs"
if ($appInit -and $appInit.AppInit_DLLs) { Write-Host "AppInit_DLLs: $($appInit.AppInit_DLLs)" -ForegroundColor Red }
else { Write-Host "No AppInit_DLLs found." -ForegroundColor Green }

# Kinda suspicious files, can cause false positives, don't blatantly believe
Write-Host "`n[Suspicious File Extensions in System Directories]" -ForegroundColor Cyan
$systemDirs = @("C:\Windows", "C:\Windows\System32")
$suspFiles = $false
foreach ($dir in $systemDirs) {
    Get-ChildItem $dir -Recurse -Depth 2 -Include *.exe,*.bat,*.vbs,*.ps1 -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike "*Windows*" -and $_.Name -notlike "*Microsoft*" -and $_.DirectoryName -notlike "*WinSxS*" } |
    ForEach-Object { Write-Host $_.FullName -ForegroundColor Red; $suspFiles = $true }
}
if (-not $suspFiles) { Write-Host "No suspicious files found in system directories." -ForegroundColor Green }

# Network Listeners 
Write-Host "`n[Active Network Listeners]" -ForegroundColor Cyan
$listeners = netstat -ano | Select-String "LISTENING"
if ($listeners) { $listeners | ForEach-Object { Write-Host $_ -ForegroundColor Red } }
else { Write-Host "No active network listeners found." -ForegroundColor Green }

# Shell Extensions 
Write-Host "`n[Shell Extensions]" -ForegroundColor Cyan
$shellExt = Get-RegistryValueSafe "HKLM:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
if ($shellExt) { $shellExt.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object { Write-Host "$($_.Name): $($_.Value)" -ForegroundColor Red } }
else { Write-Host "No shell extensions found." -ForegroundColor Green }

# Browser Helper Objects 
Write-Host "`n[Browser Helper Objects!]" -ForegroundColor Cyan
$bho = Get-RegistryValueSafe "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
if ($bho) { $bho.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object { Write-Host "$($_.Name): $($_.Value)" -ForegroundColor Red } }
else { Write-Host "No browser helper objects found this time." -ForegroundColor Green }

# Boot Execute Entries 
Write-Host "`n[Boot Execute Entries]" -ForegroundColor Cyan
$bootExec = Get-RegistryValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "BootExecute"
if ($bootExec -and $bootExec.BootExecute) { Write-Host "BootExecute: $($bootExec.BootExecute)" -ForegroundColor Red }
else { Write-Host "No BootExecute entries found, hmm." -ForegroundColor Green }

# Hidden Files 
Write-Host "`n[Hidden Files in Critical Directories]" -ForegroundColor Cyan
$hiddenFiles = $false
foreach ($dir in $systemDirs) {
    Get-ChildItem $dir -Hidden -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host $_.FullName -ForegroundColor Red; $hiddenFiles = $true
    }
}
if (-not $hiddenFiles) { Write-Host "No hidden files found in system directories, GOOD!." -ForegroundColor Green }
# Defender +Quickie Repairs 
Write-Host "`n[Updating Windows Defender Signatures]" -ForegroundColor Cyan
Update-MpSignature | Out-Null
Write-Host "Defender signatures updated." -ForegroundColor Green

Write-Host "`n[Running System File Checker (SFC)]" -ForegroundColor Cyan
sfc /scannow | Out-Null
Write-Host "SFC scan completed!" -ForegroundColor Green

Write-Host "`n[Running DISM to Repair Windows Image]" -ForegroundColor Cyan
DISM /Online /Cleanup-Image /RestoreHealth | Out-Null
Write-Host "DISM repair completed!" -ForegroundColor Green

Write-Host "`n[Checking Disk for Errors on C:]" -ForegroundColor Cyan
$diskCheck = chkdsk C: /scan
if ($diskCheck -like "*errors*") {
    Write-Host "Disk errors detected. Scheduling CHKDSK repair on reboot..." -ForegroundColor Red
    'Y' | chkdsk C: /f /r
} else {
    Write-Host "Error free! No disk errors detected on C:." -ForegroundColor Green
}

Write-Host "`n[We're performing Full Malware Scan with Windows Defender]" -ForegroundColor Cyan
Start-Job { Start-MpScan -ScanType FullScan }
Write-Host "Defender full scan started in background, this may cause your system to slowdown for a bit... Expect lag, windoez can be laggy" -ForegroundColor Yellow

Write-Host "`n[Running Microsoft Malicious Software Removal Tool (MRT) Quietly]" -ForegroundColor Cyan
Start-Job { & "$env:SystemRoot\System32\MRT.exe" /Q }
Write-Host "MRT scan running in background." -ForegroundColor Yellow

# Running through Event Logs maybe we find sum
Write-Host "`n[Checking Event Log for Shutdown Errors...]" -ForegroundColor Cyan
$shutdownEvents = Get-WinEvent -LogName System -MaxEvents 200 | Where-Object { $_.Id -in 1074,6008,41 }
if ($shutdownEvents) {
    Write-Host "! Wtf Found shutdown-related events:" -ForegroundColor Red
    $shutdownEvents | Select-Object -First 5 | Format-Table TimeCreated, Id, Message -Wrap
} else {
    Write-Host "No recent shutdown-related errors found." -ForegroundColor Green
}

# Devices with Errors 
Write-Host "`n[Checking for Devices with Errors]" -ForegroundColor Cyan
$problemDevices = Get-PnpDevice | Where-Object { $_.Status -eq 'Error' }
if ($problemDevices) {
    Write-Host "Found devices with errors:" -ForegroundColor Red
    $problemDevices | Format-Table FriendlyName, Status
} else {
    Write-Host "No devices with errors found." -ForegroundColor Green
}

# Network Stack Reset!
Write-Host "`n[Resetting TCP/IP and Winsock]" -ForegroundColor Cyan
netsh int ip reset | Out-Null
netsh winsock reset | Out-Null
Write-Host "Network stack reset completed." -ForegroundColor Green

Write-Host "`n[Flushing DNS Cache]" -ForegroundColor Cyan
ipconfig /flushdns | Out-Null
Write-Host "DNS cache flushed." -ForegroundColor Green



# WMI Repository 
Write-Host "`n[Let's Verify WMI Repository]" -ForegroundColor Cyan
winmgmt /verifyrepository
Write-Host "If inconsistencies were found you should run 'winmgmt /salvagerepository' manually." -ForegroundColor Yellow

Write-Host "`n[Attempting To Clean Temporary Files]" -ForegroundColor Cyan
Write-Host "[WARNING] The files skipped could be possibly malicious! (This is purely to avoid causing problems with currently running programs)" -ForegroundColor Yellow

# Sets the x days of old files that will be cleaned from temp
$cutoff = (Get-Date).AddDays(-7)

# Safe way to check if the file is currently in use to avoid causing problems :)
function SafeRemove-Item {
    param ($Item)
    try {
        Remove-Item $Item.FullName -Force -Recurse -ErrorAction Stop
    } catch {
        Write-Host "We've skipped in-use or protected files, you should check these: $($Item.FullName)" -ForegroundColor Yellow
    }
}

# Do the temp folder cleaning for the users file!
Get-ChildItem $env:TEMP -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $cutoff } |
    ForEach-Object { SafeRemove-Item $_ }

# Clean Windows temp folder!
Get-ChildItem "C:\Windows\Temp" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $cutoff } |
    ForEach-Object { SafeRemove-Item $_ }
Write-Host "Old temporary files cleaned up!" -ForegroundColor Green


# User Profiles 
Write-Host "`n[Checking User Profiles]" -ForegroundColor Cyan
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.Special -eq $false }
$profileIssue = $false
foreach ($profile in $profiles) {
    Write-Host "Wait a minute... Checking profile: $($profile.LocalPath)" -ForegroundColor Cyan
    if ($profile.Status -ne 0) {
        Write-Host "! Profile may be corrupted: $($profile.LocalPath)" -ForegroundColor Red
        $profileIssue = $true
    }
}
if (-not $profileIssue) { Write-Host "No user profile issues found." -ForegroundColor Green }

# Disk Space check
Write-Host "`n[Hold on a minute, checking Disk Space on C:]" -ForegroundColor Cyan
$diskSpace = Get-PSDrive C | Select-Object Used, Free
Write-Host "Disk space: Used $([math]::Round($diskSpace.Used / 1GB,2)) GB, Free $([math]::Round($diskSpace.Free / 1GB,2)) GB" -ForegroundColor Cyan
if ($diskSpace.Free / 1GB -lt 10) {
    Write-Host "Warning: Low disk space detected (<10 GB free)." -ForegroundColor Red
} else {
    Write-Host "Decent disk space available(Rookie numbers tho)." -ForegroundColor Green
}

# Top CPU Processes !!!!
Write-Host "`n[Top 10 CPU Processes for Suspicious Activity! ]" -ForegroundColor Cyan
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | ForEach-Object {
    if ($_.CPU -gt 1000000) {
        Write-Host "$($_.Name): CPU $($_.CPU), WorkingSet $($_.WorkingSet)" -ForegroundColor Red
    } else {
        Write-Host "$($_.Name): CPU $($_.CPU), WorkingSet $($_.WorkingSet)" -ForegroundColor Cyan
    }
}

# Pending Reboots 
Write-Host "`n[Checking Pending Reboots]" -ForegroundColor Cyan
$pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -or Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

# for CHKDSK checking, this will be set to true if user wants 
$chkdskScheduled = $false

if ($pendingReboot -or $chkdskScheduled) {
    Write-Host "`n[Pending Reboot Detected]" -ForegroundColor Cyan
    Write-Host "A restart is required to complete repairs (e.g., CHKDSK, pending updates, or image fixes)." -ForegroundColor Yellow
    Write-Host "Without restarting, some changes may not take effect!" -ForegroundColor Red

    # Let's ask the user before acting :)
    $response = Read-Host "Should you restart now? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "Yes sir, restarting in 30 seconds... Save your work!" -ForegroundColor DarkYellow
        Start-Sleep -Seconds 30
        Restart-Computer -Force
    } else {
        Write-Host "IMPORTANT: Please restart manually as soon as possible!" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nNo immediate reboot required, but you should consider restarting to fully apply changes!" -ForegroundColor Green
}

Write-Host "`n Bob Finished the Scan! Review the log for full info, it's saved in $logPath as previously stated!" -ForegroundColor Green
Stop-Transcript | Out-Null
pause
