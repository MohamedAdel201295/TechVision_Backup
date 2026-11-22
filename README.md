# TechVision Backup MVP

A lightweight backup solution built with Electron for Windows.

## Features

- Full backup with ZIP compression
- Incremental backup support
- SHA-256 hash verification
- Locked file handling (EACCES/EPERM)
- Restore with streaming extraction (memory efficient)

## Phase 1 Features (Completed)

- ✅ Streaming restore with yauzl (replaced adm-zip for memory efficiency)
- ✅ Locked file detection and handling (SKIPPED-LOCKED)
- ✅ 50MB+ file support with streaming extraction
- ✅ Long path support (>260 chars)

## Known Limitations

**VSS (Volume Shadow Copy) is NOT implemented.**

Locked files are skipped with SKIPPED-LOCKED error code. Full VSS support via `vssadmin` or PowerShell is a later phase.

> **Note:** This is by design for the MVP. File backup uses direct file reads. Locked/permission-denied files are logged as SKIPPED-LOCKED and the backup continues. VSS integration will be added in a future phase.

## Installation

```bash
npm install
npm run build
```

## Usage

```bash
npm start      # Start development
npm run build  # Build Windows executable
```

## Project Structure

```
techvision-electron/
├── src/
│   ├── main.js           # Electron main process
│   ├── preload.js        # Context bridge for IPC
│   ├── renderer.js       # UI logic
│   ├── techvision-core.js # Backup engine
│   ├── restore.js        # Restore engine
│   ├── index.html        # Main UI
│   ├── job-wizard.html   # New Job wizard
│   ├── restore-wizard.html # Restore wizard
│   ├── log-viewer.html   # Log viewer
│   └── styles.css        # UI styles
├── package.json
└── README.md
```

## Phase 2 Roadmap

- [x] Job management UI (New Job wizard)
- [x] Restore wizard
- [x] Log viewer
- [ ] Settings panel
- [ ] Notification system
- [ ] Dark/light theme toggle

## Technical Details

### Streaming Restore

Uses `yauzl` for memory-efficient ZIP extraction:
- Streams entries one at a time
- No full ZIP load into memory
- Prevents OOM on large backups

### Locked File Handling

When a file cannot be read (EACCES/EPERM):
1. File is logged as `[SKIPPED-LOCKED]`
2. Backup job continues
3. Count reported in `locked_files_skipped` field
4. No VSS/shadow copy attempted

### Dependencies

| Package | Purpose |
|---------|---------|
| electron | Desktop app framework |
| electron-builder | Windows x64 packaging |
| archiver | ZIP creation |
| yauzl | Streaming ZIP extraction |
| crypto-js | SHA-256 hashing |

## VSS Implementation (Future)

VSS will be implemented via:
- PowerShell `Get-VolumeShadowCopy`
- `vssadmin create shadow`
- File staging before backup

Current MVP: Locked files skipped with logging.

## 📦 GitHub Repository

🔗 https://github.com/MohamedAdel201295/TechVision_Backup

## License

MIT License