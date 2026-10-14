# DCleaner architecture

## Decision ADR-001 — Accepted: fully native Rust

The user requires all application UI and logic in Rust. egui/eframe renders native desktop windows; one Rust application service coordinates workers and platform operations. React/Electron and Tauri were superseded before delivery. Their temporary prototype remains outside the repository.

Alternatives: Tauri preserves HTML/CSS components but includes a JavaScript/webview UI, conflicting with the accepted requirement. Flutter is not Rust. Native Rust requires reproducing the accepted screenshot composition through shared painted controls and inspecting the native output.

Consequences: shared core contracts across Windows/macOS; native builds on each OS; platform permissions, Trash behaviour, signing and installation remain OS-specific. Local cleaning needs no server. Cloud cleaning and independent update catalogues require authenticated external providers and capability setup.

## Owners

| Module | Authoritative responsibility | Allowed effects |
| --- | --- | --- |
| `src/domain.rs` | Analysis, file candidate, category, cleanup outcomes and settings contracts | None |
| `src/platform.rs` | Explicit OS cache-root catalogue and durable app-data directory | Environment/known-directory reads |
| `src/scanner.rs` | Bounded traversal, file eligibility, canonical containment, snapshots | Read files/metadata |
| `src/cleanup.rs` | Validate IDs against the analysis, recheck eligibility, journal intent/outcome, coordinate Trash | Only selected current candidates through Trash adapter |
| `src/store.rs` | Versioned settings and append-only cleanup journal, interrupted-operation projection | DCleaner app-data writes |
| `src/effects.rs` | Synced typed native intents and receipts; uncertain restart history | DCleaner app-data writes; no automatic replay |
| `src/duplicates.rs` | Bounded fingerprinting, exact-content verification, group metadata and selected candidate IDs | File/metadata reads; delegates reviewed removal to cleanup |
| `src/programs.rs` | Native registered-program inventory and current-identity uninstall requests | Registry reads; reviewed direct registered-uninstaller handoff |
| `src/startup.rs` | Four startup source inventories, exact before/after change and restoration contracts | Native reads; reviewed, journaled and verified supported writes |
| `src/software.rs` | Exact package/source/registration identity, independent update discovery and installed-version verification | Explicit source reads; reviewed journaled external installer execution |
| `src/drivers.rs` | Present-device inventory, WUA offer/device identity, skip/ignore settings, reviewed package backup/update/restore and receipts | SetupAPI/WUA reads; exact reviewed, journaled driver actions with restore-point and signed-package prerequisites |
| `src/health.rs`, `src/view_health.rs` | Privacy -> Space -> Resolve Issues workflow, current scan IDs, selection, review, per-owner progress/outcomes and summary | Delegates reviewed plans to existing owners; never invents an independent cleaning/update engine |
| `src/clean_settings.rs` | Versioned Custom Clean inclusions/exclusions, rule choices and deletion/age preferences recovered from the shipped UI contract | Validated atomic preference writes only; stored choices currently authorize no cleaning, wiping, process closure or shutdown |
| `src/privacy.rs` | Known-schema browser record inventory, conflict detection, selected transactional cleanup and recoverable snapshots | Read-only scan; reviewed database effects only after schema/consistency verification |
| `src/recycle_bin.rs` | Current-user shell Recycle Bin inventory, immutable item identities and reviewed restore/purge | Only exact reviewed items; synced intent, fresh native revalidation and outcome verification |
| `src/instance.rs`, `scripts/install.ps1` | One interactive process per Windows session and one stable user install/shortcut path | Session mutex/window activation; scoped executable/shortcut replacement; preserves app data |
| `src/view_duplicates.rs`, `src/view_programs.rs`, `src/view_startup.rs`, `src/view_software.rs`, `src/view_privacy.rs`, `src/view_recycle_bin.rs` | Feature state, actual result tables and review dialogs | Typed service requests; journal must succeed before native effect |
| `src/theme.rs` | Semantic colours, font, spacing, frame/row/button tokens | Paint only |
| `src/app_icons.rs` | Bounded asynchronous application artwork cache | Reads local registered icon resources/executables only; never launches a locator, invokes a shell or downloads guessed artwork; absent artwork preserves the column slot |
| `src/app.rs` | Navigation, selection, review, native dialogs and background-worker messages | Calls services; no unrestricted deletion |
| `src/main.rs` | Native startup and read-only diagnostic entry point | Window creation / explicitly requested diagnostics |

The UI sends typed Rust commands directly to the application service. Scan results carry opaque UUIDs and immutable file metadata. The cleanup service resolves IDs from the current analysis and never accepts caller-supplied deletion paths. Worker completion is observed via a bounded/single-operation channel; no second authoritative database model lives in the UI.

## Commands and transitions

`Idle -> Scanning -> ReviewedAnalysis | CancelledAnalysis | Failed`.
`ReviewedAnalysis -> Confirming -> Cleaning -> Completed | PartiallyCompleted | Interrupted`.
`Idle -> FolderAnalysis -> ReadOnlyResults | Cancelled | Failed`.

An active operation rejects another operation. Changing cleaning settings invalidates the old analysis. Cancelled analyses cannot authorize cleanup. Cleanup success counts only completed Trash calls whose receipt was durably written; uncertain operations are separated on restart. The UI does not infer success from elapsed time, progress, file absence or a selected checkbox.

Each row owns its real supported controls: details/review/more, selected-ID changes, reversible startup state or update request. The pinned footer summarizes the same state; it is not the only route to per-row actions. An unsupported effect exposes its exact limitation and stays an open parity obligation.

Startup state belongs to Windows, including changes made by other tools. User and common Startup folders resolve their own StartupApproved hives (HKCU and HKLM respectively); inventory, preflight, effect and restoration must use the same source identity. Returning to the foreground and periodic visible-page refresh re-read state, preserving selection by stable identity. Never overwrite externally disabled state with a UI default or infer Enabled from a failed source read.

Browser privacy uses known profile roots and actual supported database schemas. Scan projections contain category/site metadata without cookie secrets. Cleanup resolves current opaque record IDs, applies persistent cookie keep rules, checks browser conflicts, snapshots and syncs recovery material, then uses a transaction. Restore is a separate reviewed effect: only the exact unchanged post-cleanup database may be replaced from its validated snapshot while the browser is closed. A changed database or uncertain journal blocks restoration; backups are preserved and no interrupted effect is replayed automatically.

Driver state separates installed metadata, native property-read failures and exact WUA offers. A missing offer is not proof that a driver is current; WUA does not supply a candidate driver version through the used interface. Ambiguous device/offer matching blocks an update intent. Reviewed update order is exact preflight, synced intent, restore point, verified signed installed-package export, fresh preflight, exact WUA download/install, aggregate and per-item status, reboot classification and actual device verification. Restore has its own exact backup/device identity and journal. Batch offers deduplicate update GUID/revision/source, stop on failure/uncertainty/pending restart, and state that a shared offer's verification covers its representative device rather than all grouped devices. Native install/restore cancellation and post-reboot verification remain open; Windows is never restarted automatically.

Health Check starts from the accepted finding-card landing view. Only Start Health Check begins browser/cookie prerequisites; app launch does not itself request browser closure. Each step owns scanning, browser conflict review, current finding selection, exact action review, cancellation, partial/failed results, skip/advance and final summary. Cookie-rule errors block Privacy rather than unrelated Space/Resolve Issues scans. The Health coordinator resolves service-owned IDs into plans and consumes typed receipts. Native owner calls that cannot be interrupted observe cancellation only after return. Startup inventory does not classify an app as unnecessary; Driver Updater and background optimization are not yet included in this Health scan. Those gaps remain explicit rather than inferred from dedicated-section availability.

Recycle Bin is a separate effect owner from filesystem Trash moves. Inventory exposes scan-local UUIDs and shell metadata; callers cannot supply deletion paths or native tokens. Restore and permanent purge require a complete reviewed inventory, readable journal, fresh identity/metadata comparison and durable per-item intent. Purge has an additional irreversible-action acknowledgement. Failed post-effect observation remains uncertain, and no automatic retry follows restart. Folder entry counts are never represented as bytes; the underlying shell enumeration is non-cancellable until its first native call returns.

## Persistence and recovery

Custom Clean has a separate configured scan owner (`custom_clean`). Its private report retains exact file IDs, settings identity, eligible rule IDs and scan-time cutoffs; its serializable `Analysis` projection is display data marked `CleanupPolicy::CustomCleanRules`. The legacy age-only cleanup API rejects that policy before journaling. Configured cleanup resolves the whole selected-ID set, current saved-settings identity, partial-result acknowledgement and unsupported-effect constraints before the shared effect loop. That loop always checks root containment, link/reparse state and unchanged file metadata before the owner policy and system Trash call. Secure erase, folder-self removal, registry/cookie exclusions, free-space/ADS/MFT wiping, shutdown and close-process handling do not gain execution support from stored preferences.

The configuration dialog edits a draft and saves through the strict versioned settings store. Successful saving invalidates prior file results; scanning and cleaning load authoritative settings rather than treating the editor draft as authority. Exports retain the configured report, including omissions and per-rule eligibility. File and path exclusion matching is an explicit independent DCleaner policy; shipped request fields do not establish original native matching semantics. Built-in cache rules retain the existing minimum-age preference, while explicit inclusions use their own optional hour threshold. The 24-hour preference is limited to the supported built-in temporary-file rule. This preserves current behavior without claiming the original engine has been reproduced.

`DeferredJournal` opens no operation file until the first Start event, after preflight succeeds. Invalid settings, unsupported effects or stale IDs therefore do not leave empty operation files that would make History unreadable. Durable intent/outcome and uncertainty rules remain the same once an operation begins.

Schema version 1 settings are replaced atomically through a same-directory temporary file. Per-operation JSON-lines journals record `start`, `intent`, `outcome`, `finish` with stable UUIDs. Each consequential journal entry is flushed and synced. Failure to preserve an intent prevents that file's Trash move. Failure after a move leaves an uncertain intent; no automatic retry follows restart. History is derived from journals and retains exact confirmed outcomes plus uncertainty. Invalid/truncated journals expose a recovery warning and preserve original bytes.

Windows stores DCleaner data in the user's local application-data directory. macOS uses `~/Library/Application Support/DCleaner`. Application replacement does not replace those directories. Source references, private path reports, credentials and user data stay out of Git. Exports are explicit native Save dialog actions.

## Design contract ADR-002 — Superseded; ADR-003 — Accepted

The user explicitly dropped Audyt and shadcn on 15 October 2026. Current visual authority is the supplied navy desktop screenshots and Designer skill in DESIGN.md. CCleaner screenshots define functional sections, tabs, options and transitions. UI and operations remain fully Rust; implement the complete section map in PLAN.md. All screenshot-based controls must connect to real typed services and truthful state.

## Capability boundaries

Baseline cleaning reads user-local temp/cache directories, skips links and recent/changed files, and uses system Trash. Registry changes, updates, secure erase, auto-emptying Trash and privileged locations need distinct typed services, explicit review/authorization and capability/recovery designs. 100% parity is a tracked acceptance target rather than a percentage inferred from menu count.

Architecture guidance: [the user's Architecture skill](https://drive.google.com/file/d/1mP5x-ep4llBg6wfkpWPRujkX4SsJA_tJ/view). UI review: [Designer skill](https://drive.google.com/file/d/1IrMVEvvV6xizNl_aTHC_KR-5JNYn3F9k/view).

## Background verification and desktop boundary

The user requires confirmation before one inspection install and prohibits desktop/app/capture actions until then. Source work and background tests continue. Read-only WinGet inventory and the noninteractive pnputil export helper use `CREATE_NO_WINDOW`; the reviewed interactive update installer remains a separate explicit user operation.

The debug-only `src/offscreen_qa.rs` prepares CPU rasterization of the same egui tessellation, using `App::new_with_context` and `App::paint` without invoking eframe window creation or session-instance activation. It requires explicit isolated data/output paths, applies texture patches, clips and alpha blends meshes, rejects unsupported paint callbacks, and labels its output as software/layout evidence rather than a native framebuffer or installed acceptance. Pure rasterizer tests cover shared-edge blending/scissoring and bounded texture updates. Automatic approval review rejected execution of the app's offscreen entry point under the user's restriction; no offscreen app capture has run. Do not invoke it through an alternate harness/path to circumvent that rejection. Installed/GPU/interaction evidence remains separate and pending approval.
