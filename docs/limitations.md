# Limitations — RegEx Acquisition Engine

Although RegEx aims to provide a complete, safe, and reliable collection workflow,
certain limitations are unavoidable during live acquisition.

---

## ❗ 1. User Hive Locking
NTUSER.DAT and UsrClass.dat may be locked if:
- User is actively logged in
- Processes hold exclusive handles

Result:  
✔ Best-effort copy  
✔ Hash stored  
✘ No deep guarantee of full completeness

---

## ❗ 2. VSS Restrictions
If Volume Shadow Copy Service is:
- Disabled  
- Restricted by policy  
- Corrupted  

RegEx falls back to:
✔ Direct read-only copy  
✘ No snapshot-based consistency

---

## ❗ 3. Event Log Access Restrictions
Security.evtx may fail if:
- Admin privileges are missing  
- System policies restrict extraction

RegEx logs these failures but continues.

---

## ❗ 4. WinPE Limitations
In WinPE:
- Prefetch typically unavailable  
- Amcache often missing  
- USB history partially populated

This is expected.

---

## ❗ 5. Damaged / Corrupted Systems
Artifacts on systems with:
- Filesystem corruption  
- Damaged hives  
- Broken ACLs  

may only be partially recoverable.

---

## ❗ 6. No Memory Acquisition
RegEx does not collect:
- RAM dumps  
- Pagefile  
- Crash dumps

(RegEx focuses solely on disk-based registry + metadata artifacts.)

---

## ❗ 7. Not a Full DFIR Suite
RegEx is a **collection tool**, not an analysis engine.  
Analysis is performed using the companion project:
**RegEx-Analysis**
