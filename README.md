# RegEx Acquisition Engine (v1.0)
### PowerShell-Based Forensic Artifact Collector  
**Developed by Arnab Das**

RegEx Acquisition Engine is a Windows forensic collection tool focused on
safe, structured, repeatable acquisition of registry hives, event logs,
USB artifacts, prefetch data, Amcache, and system metadata.

It is designed to operate on:
- Live systems  
- Restricted Windows builds  
- WinPE environments  
- Air-gapped forensic workflows  

---

## 🔥 Features
- Standalone PowerShell acquisition (no Python required)
- Fallback-safe collection even if VSS is restricted
- Creates **manifest.json** with SHA256 integrity hashes
- Collects:
  - SYSTEM, SAM, SECURITY, SOFTWARE, DEFAULT hives
  - User NTUSER.DAT & UsrClass.dat (best-effort)
  - Event logs (System, Application, Security)
  - USB history (Enum\USBSTOR + MountedDevices)
  - Prefetch files
  - Amcache (best-effort)
- Generates:
  - regex_log.txt (chain-of-custody log)
  - operation_summary.txt
  - usb_history.csv
- Clean directory structure ready for analysis by *RegEx-Analysis*

---

## 📁 Output Structure
After running the script, you get:

