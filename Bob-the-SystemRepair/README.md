👷‍♂️ Bob-the-SystemRepair PowerShell Script 👷‍♂️
====================


A simple, yet reliable PowerShell script for a deep Windows system scanning and repair. I made this for for quick reviews and fixing common issues, but also doing a deep system scan and logging everything. 

Basically Bob:
- Provides color-coded console output based on severity!
- Logs all key findings into your desktop as a log file for later review!
- Performs deep system checks and repairs (including SFC, DISM, Windows Defender, etc, you can read more below).


> ⚠️ **Warning:** ⚠️ 
> Script is *unsigned* (Signing a PowerShell script is not cheap 😭). Run with:  
>
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
>```
> To run safely for this session only!
> Inspect the code if you want to!
> 
> Make sure to execute as **Administrator**! Scan will not start without elevated privileges, as it would otherwise do a very lacking scan.  
> 🛡️ Results from Defender full scan and MRT are **not** saved in `BobScans.log`.

***

## Features of Bob-the-SystemRepair!
 [Please, remember that Bob mostly flags suspected things but doesn't automatically remove them for obvious reasons.]
 
- **Deep system scan:**  
  - Startup folders and Registry autoruns  
  - Scheduled tasks, WMI event consumers  
  - Winlogon keys, IFEO hijacks, AppInit DLLs  
  - Shell extensions, Browser Helper Objects  
  - Suspicious files in Windows/System32  
  - Hidden files in system directories
- **Live repair actions we will take!:**  
  - Updates Defender signatures  
  - Background malware scan (Defender, MRT)  
  - System File Checker (SFC) and DISM image repair  
  - Disk error checks, auto-fix if needed
- **Network & device checks:**  
  - Non-standard services and network listeners  
  - Event log for shutdown errors  
  - Device hardware status  
  - Disk space, pending reboot detection
- **Additional fixes and cleaning Bob does:**  
  - TCP/IP and Winsock resets  
  - DNS cache flush  
  - WMI repository verification  
  - Cleans old temp files (skips in-use/protected)

***

## 🔍 Usage

1. **Open PowerShell as Administrator**
2. Set execution policy (required):  
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. Run the script:  
   ```powershell
   .\Bob-the-SystemRepair.ps1
   ```
   [Note that you need to be in the directory to actually run the file, or specify it]
***

## 🚦 Output

- **Live console display** with color highlights:
  - 🔴 Suspicious findings, **check carefully but don't be spooked!**  
  - 🟡 Important findings!
  - 🟢 All clear/good results, basically positive or neutral things 

- **Log file:**  
  All PowerShell console output (except Defender/MRT scan details) is saved to:  
  ```
  <YourName>\Desktop\BobScans.log
  ```

***

## Important Warnings for you to know about!

- **Do not interrupt the scan!** Canceling repairs may cause unexpected problems.
- **Review flagged entries manually** false *positives* are very possible, but don’t ignore red flagsd by default.
- **Restart required:** Some repairs won't take effect without rebooting. *Script will prompt if one is needed though!*.
- **Skipped temp files:** Skipped files may still be malicious! Investigate further if you're concerned, you should review the log either from the file or via log output!
  

***

## Note this:
Bob is best used by users with basic PowerShell and Windows admin skills, although it's very much usable by anyone on any skill level as long as you can turn your computer on!

! Always review the log and flagged items before making system changes !
