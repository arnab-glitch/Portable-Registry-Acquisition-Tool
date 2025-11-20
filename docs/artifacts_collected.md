# Artifacts Collected by RegEx Acquisition Engine

This document explains each artifact collected, why it matters, and how it contributes to
forensic reconstruction.

---

## 🧱 1. Registry Hives (HKLM + HKU)

### SYSTEM
- Boot configuration
- Mounted devices
- Timezone
- Hardware profile

### SOFTWARE
- Installed applications
- OS configuration
- System-wide settings

### SAM
- Local accounts
- User metadata
- Login password hashes (non-cracked)

### SECURITY
- LSA secrets
- Policies
- Audit settings

### DEFAULT
- Default user profile

### NTUSER.DAT
- User-specific activity
- MRU lists
- Application histories
- Explorer activity

### UsrClass.dat (best-effort)
- ShellBag data
- Folder interaction history

---

## 🧲 2. Event Logs

### System.evtx
- Driver issues
- Device attach/remove
- System faults

### Application.evtx
- Application errors
- Software crashes
- Runtime activity

### Security.evtx
- Logon events
- Audit logs
- Privilege usage

---

## 💻 3. USB Artifacts
- USBSTOR entries (device model/vendor/serial)
- MountedDevices (drive letter assignment)
- First/last connected timestamps (best-effort)
- Volume GUIDs

Creates:
`usb_history.csv` — formatted for correlation in analysis stage.

---

## 🚀 4. Prefetch Files
- Execution metadata
- Run counts
- Last execution timestamps
- File access patterns

Useful for:
- Program execution verification
- Timeline building
- Malware triage

---

## 📦 5. Amcache
- Program installation history
- Executed binaries metadata
- SHA1 + file path info
- First/last execution timestamps

---

## 🧾 6. Metadata & Logs Generated

### manifest.json
Contains:
- SHA256 hashes
- File sizes
- Timestamps
- Paths
- Flags for failed/partial extractions

### regex_log.txt
- Step-by-step chain-of-custody log

### operation_summary.txt
- Operator
- Case ID
- System info
- Acquisition duration
