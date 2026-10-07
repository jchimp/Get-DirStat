# Get-DirStat

WinDirStat-style disk usage report for Windows PowerShell 5.1. Built to run from NinjaOne (or any RMM) as SYSTEM.

- **Stdout:** plain-text summary for the NinjaOne activity log. It shows User data vs OS/Programs vs Other vs Unaccounted, category totals, per-profile totals with the largest folders, and the largest files.
- **HTML:** one self-contained file in `C:\ProgramData\DirStat\` with a drill-down folder tree. It needs no internet. The last 5 reports for each computer are kept.

## Requirements

- Windows PowerShell 5.1 and .NET Framework 4.x. Both ship with Windows 10/11 and Server 2016+.
- The C# scanner is compiled at runtime by `Add-Type`, which uses the built-in `csc.exe`. If EDR/AV blocks this, the script exits with code 1 and says so.
- Run elevated or as SYSTEM. If not, other profiles and system folders show as "access denied".

## Usage

```powershell
.\Get-DirStat.ps1                                  # System drive, depth 5
.\Get-DirStat.ps1 -Path 'D:\' -MaxDepth 6
.\Get-DirStat.ps1 -Path 'C:\Users' -MinSizeMB 100 -TopFiles 50
```

| Parameter | Default | Purpose |
|---|---|---|
| `-Path` | `$env:SystemDrive\` | Folder or drive root to scan. |
| `-MaxDepth` | `5` | Tree levels kept in the HTML (2-20). |
| `-TopFiles` | `20` | Largest files to list. |
| `-MinSizeMB` | `50` | Smaller folders fold into one row in the HTML tree. |
| `-OutputDir` | `$env:ProgramData\DirStat` | Where the HTML goes. |
| `-KeepReports` | `5` | Reports kept for each computer. `0` keeps all. |

Exit codes: `0` OK, `1` error (bad path, compile blocked, or HTML write failed).

## How it counts

- Every file is read, so totals are exact. `-MaxDepth` only limits the HTML tree. It does not make the scan faster.
- Junctions and symlinks are skipped to prevent double counting. OneDrive folders are scanned.
- OneDrive cloud-only files are not counted, because they use no local disk. They are listed in Notes.
- **Unaccounted** = drive used space minus scanned files. This is NTFS metadata, denied folders, and similar items.
- Sizes are logical sizes. WinSxS hard links and NTFS compression can make scanned totals larger than real disk use.
- "Largest folders" drills into the biggest folder while one child holds 25% or more of it. It stops at `-MaxDepth`.

## Privacy

The HTML lists file paths for all profiles. `C:\ProgramData\DirStat` inherits the ProgramData ACL, so local users can read it.
