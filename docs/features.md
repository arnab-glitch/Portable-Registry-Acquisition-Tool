# RegEx Acquisition — Feature Summary

RegEx is a portable, zero-install Windows forensic collection tool built for
live response, WinPE operations, and USB-based triage workflows.

---

## 🔥 1. Core Capabilities
- 100% PowerShell (no Python, no external dependencies)
- Runs directly from a USB device (no installation or system modification)
- Safe live acquisition with read-only operations
- Works on:
  - Live Windows hosts
  - WinPE / rescue media
  - Air-gapped forensic setups
  - Restricted Windows environments

---

## 📂 2. Supported Artifact Collection
- **Registry Hives**
  - SYSTEM, SAM, SECURITY, SOFTWARE, DEFAULT
  - User NTUSER.DAT
  - UsrClass.dat (best-effort)
- **Event Logs**
  - System, Application, Security
- **USB Artifacts**
  - USBSTOR
  - MountedDevices
  - DeviceClasses (best-effort)
- **Prefetch Files**
  - All *.pf entries
- **Amcache**
  - Root and RecentFileCache (best-effort)

---

## 🔐 3. Integrity & Logging Features
- SHA256 hashing on all extracted artifacts
- `manifest.json` for full metadata + hash tracking
- `regex_log.txt` for chain-of-custody events
- `operation_summary.txt` for operator/time/session details

---

## 📦 4. Evidence Folder Structure
- Clean, standardized output directory:
  - Extracted_Hives/
  - Event_Logs/
  - Prefetch/
  - Amcache/
  - Registry_Exports/
  - usb_history.csv
  - manifest.json
  - regex_log.txt
  - operation_summary.txt

---

## 🚀 5. Performance & Reliability
- Fallback-safe extraction when VSS is blocked
- Automatically detects available registry paths
- Minimal memory usage (triage-friendly)
- Works even on corrupted or partially damaged systems

---

## 🧩 6. Integration With RegEx-Analysis
Output fully compatible with:
- Automated timeline generation  
- Registry parsing  
- USB correlation  
- Amcache & Prefetch processing  
