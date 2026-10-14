# DCleaner implementation plan

Accepted scope: fully Rust UI and services; DCleaner; cocombee/DCleaner Git destination; complete functions, sections and workflows matching CCleaner Windows 7.12.1526; Mac design and parity plan for 2.11.194. The user's supplied navy screenshots define visual design. Audyt and shadcn have been explicitly dropped.

Goal amendment, explicitly requested by the user: **no omissions**. Do not stop at a subset or declare completion while any original function, section, tab, row action, menu, dialog, setting, consequential state, persistence or recovery path is missing or unverified. The native design must be compared against the supplied design references down to pixel geometry, typography, spacing, colours, icons and control states at the supported sizes. Every uncovered or inaccessible case remains an open obligation; it must not silently disappear from scope. Runtime, functional and visual acceptance each require their own evidence. The latest screenshot design replaces the goal tool's older Audyt/shadcn wording.

Desktop constraint, explicitly requested after capture batches interrupted the user's mouse: **nothing physical until the user confirms one install for inspection**. Do not automate mouse/keyboard, launch application windows, run live GUI captures, install, or replace the existing installed application before that confirmation. Continue source work, background tests that do not launch GUI windows, and inspection of already saved images. Prepare one reviewable candidate; keep any live/installed visual checks pending. This supersedes earlier blanket autonomy for desktop/install actions. Preserve the single canonical installation rather than creating a second copy.

Automatic approval review also rejected execution of the application with `--render-offscreen-qa`, interpreting the restriction to include that app launch/capture. It did not execute. Do not retry that route indirectly or through a harness, alternate path, wrapper, sandbox change or renamed executable. Offscreen-renderer source and pure renderer tests may be prepared, but app-render execution remains pending the user's inspection approval.

Use the existing Architecture skill, this plan and ARCHITECTURE.md. DESIGN.md is the one added design-evidence file. Keep skill sources intact. Do not create separate Markdown reports/ledgers; record each batch here and raw/private evidence in ignored reference storage.

## Completion gate and implementation order

The nine main sections, all settings/help pages, every subtab, option, detail/confirmation dialog, progress/cancel/error/result state and persistence/recovery path remain required. A menu entry, adapter, model, passing unit test, static graph or plan does not close a workflow. No scope reduction to the existing prototype is accepted.

1. Reconcile the authenticated shipped UI/service/native evidence with original screenshots and reachable runtime states.
2. Define each module, typed request/result, authoritative data owner, permission boundary, consequential effect, durable intent/receipt and restart recovery before wiring its UI.
3. Implement complete feature slices, with actual native adapters and independent provider data. Add appropriate meaningful tests and actual native checks.
4. Apply the screenshot design through shared Rust shell, rail/section navigation, result tables, controls, progress, dialogs and pinned footers. Review every implemented state at wide/minimum size and default navy/optional light.
5. Publish the verified source/checkpoints to the requested repository. Keep the goal active and every remaining obligation visible until full acceptance is met.

## Original workflow observations supplied by the user

These are original CCleaner layout/functional captures, not visual styling references. The raw captures are preserved privately in reference/ccleaner/user-captures. They supplement shipped-artifact analysis; they do not prove a DCleaner operation works. Never reuse their personal metrics or installed-app data as production/example data.

| Feature | Required layout, controls and transitions observed |
| --- | --- |
| Health Check | Browser-close multi-selection dialog (select all, individual running browsers, Cancel, close selected); More privacy -> More space -> Resolve issues stepper; scan/clean progress ring and Stop; category expansion/selection, size and item counts, cookie settings, Skip/Clean/Resolve; privacy categories internet temporary files, cookies and browsing history; space categories Recycle Bin, temporary system files and application cache; issues include unnecessary startup apps and outdated applications; final summary and cross-feature handoffs remain to verify |
| Custom Clean | Junk, Browser and Registry tabs; Configure; category tree with checked/partial selection and expansion; Windows, System, Applications, Utilities, Multimedia, Windows Store, Downloads, AI Tools, Advanced and Internet groups; selected count, Scan now, Clean and fix; group contents/configuration/result dialogs remain to inspect |
| Duplicate Finder | Drives versus specific folders, All drives/individual drives, refresh and Scan all; original settings include minimum size64KiB, hidden/system/read-only/compressed flags, file-type filtering, duplicate detection and keep-oldest/newest/select-all/deselect-all; original oldest/newest uses creation time; group/file details and deletion warnings remain required |
| Startup Manager | Startup apps, Scheduled tasks, Context menu, Windows services; program/publisher/path/current state, sort, switches and more menu; tab content, details/export/delete/restore/error states remain required |
| Performance Optimizer | Active, Sleeping and Excluded apps; measured impact, per-app Sleep and more menu, scan again; actual sleep/wake/exclusion/restart semantics must be traced before claiming equivalence |
| Driver Updater | Outdated, Up-to-date, Skipped & Ignored; device-category grouping, selection, version/release columns, more menu, Fix a problem, Scan again, Update selected; backup/rollback/download/install/reboot/error states remain required |
| Cloud Drive Cleaner | Original native intro launches an external flow; provider choices Google Drive, OneDrive, Dropbox and Google Mail; connect/switch accounts, duplicate/large/clutter review, selection and removal; legitimate independent provider authorization and contracts required |
| Software Updater | Main section and shipped routes/state owners observed; outdated/up-to-date/skipped/ignored tabs, app/Windows update grouping, severity/details and result/reboot/error contracts recovered statically; live page and remaining transitions still required |
| Uninstaller | Main section and shipped installed/disabled scan/remove/disable/enable journeys; details, search/sort, temporary uninstall/simulator, cleanup30/90/120days and restoration obligations; live page still required |
| Settings and Help | General, Menu Layout, Scheduling, Updates, Privacy, My Subscription, About plus Help; exact controls and production reachability of conditional Debug/Statistics/Ideas Portal remain required |

## Service owners and implementation slices

| Owner | Required responsibility and acceptance |
| --- | --- |
| domain/scanner/cleanup/store | Current immutable IDs, bounded read-only scan, metadata/link/containment validation, system Trash with synced intent/outcome, cancellation and uncertain restart projection. Extend cleaning rules/privacy/registry/secure erase/Recycle Bin through separate reviewed effects; do not equate cache cleanup with full Custom Clean |
| duplicates | Streaming content fingerprint plus exact comparison, drives/folders/options, groups and creation-time bulk selection, current-ID cleanup review; changed/unreadable/link/partial handling; no all-members cleanup without explicit warning acknowledgement |
| programs | Native install registration inventory/details, protected/current-app exclusions, registered-command revalidation and direct uninstall handoff; separate completion observation; temporary disable/enable and expiry/restore require their own durable effect implementation |
| startup | Four native category inventories, stable source identity and explicit unknown/denied states; reversible selected changes with journal-before-effect, compare-and-set, verify and restore; complete each tab's controls rather than only registering labels |
| optimizer | Actual installed-app/background/startup/service association; measured impact and independently verified sleep/wake/exclusion semantics; own recovery service/leases if required; never substitute process termination or synthetic impact |
| software/driver updates | Independent catalogue, installed-version/device identity, severity/details, skip-version versus ignore-item, signed/authenticated installer acquisition, cancellation, progress, reboot, backup/rollback where original requires it; launch is not completion |
| cloud | Provider authorization/refresh and secure credential storage, paged storage/mail metadata, duplicate/large/clutter inventory, selected remote operations, provider Trash/recovery and partial failures; no copied vendor credentials or licence bypass |
| health | Orchestrates actual privacy/space/issues services with browser conflict handling, per-step selection/skip/review/effect/results; no fabricated health percentages |
| settings/scheduling/help | Original option families, durable validation and restart, native scheduler tasks/permissions, own app update/edition/help semantics, exports, accessibility and readable failure states |

All application UI and logic remain Rust. Native OS utilities or registered uninstallers are external operations, not implementations of the missing Rust services. Original proprietary service data is not automatically available to DCleaner; model external capability setup and test the genuine integration rather than simulating success.

## Current verification

The original11 core tests passed outside the Windows filesystem sandbox. A separate isolated native Recycle Bin roundtrip passed: move a newly created fixture, verify the durable receipt, locate only that exact fixture and restore its bytes. Sandbox failures on atomic replacement/junction fixtures were rerun on native NTFS and passed. The first release executable built, but its visual design is superseded by the latest references and is not final acceptance.

The latest integrated verification on native NTFS passed **148 ordinary tests**, with six explicitly opt-in native checks excluded. Rust formatting and the native release build passed. This includes 28 driver tests, 11 Health coordinator tests, nine Custom Clean settings tests, two pure software-rasterizer tests, native executable-icon extraction with transparent pixels, registry artwork metadata/backward compatibility, browser discovery, cleanup/recovery and the existing feature suites. Duplicate Finder, Uninstaller, Startup Manager, Software Updater, Driver Updater, staged Health Check, browser privacy and Recycle Bin page/footer/dialog flows are connected in source; this does not establish native end-to-end parity. Browser fixture tests cover actual-shaped schema dependencies, selected transactions, snapshots, conflict/changed-state rejection and guarded restoration; full browser semantics remain open. Recycle Bin restore/purge uses per-item durable intents and fresh native validation; the actual user's items were not modified during QA. Sandbox discovery had incorrectly appeared empty: a native read found nine supported browser profiles, so a sandbox zero must not be treated as the machine's state.

Current uninstalled candidate release SHA-256: `4EDB9740D0902E3C1D21C27A369F1F1917184B3D6BDDFD1FE59763A1F8E4EF60`. The existing canonical installation remains untouched pending the user's single-install inspection confirmation. The new Driver/Health states, compact rail correction and final scrollbar paint have not been captured or accepted. Custom Clean's new strict, versioned preferences cover the observed inclusion/exclusion, rule-selection, age/deletion and advanced options schema, with corrupt/future bytes preserved across attempted saves; they are stored-only until the rule engine/configuration UI is connected. Secure erase, free-space/ADS/MFT wiping, shutdown and skipped-process handling remain unimplemented effects, not features implied by a saved option.

Startup's common-folder approval hive is corrected and independently checked against the raw HKLM marker: Audient is Disabled and its row offers Enable. Shortcut targets and file-version metadata provide the actual publisher and version; the native window shows Audient as publisher. Foreground/periodic external-state refresh is read-only and runs separately from effect workers. Row headers stay outside bounded body scrollers. Application logos are read asynchronously from local native icon resources, with a fixed-width slot and an explicit missing-artwork fallback; no guessed web brand icons or execution of icon locators. Native maximize/restore and idle QA-window close were exercised; minimize/resize, all row effects and all-state parity remain open.


# Parity ledger

Target: CCleaner Windows 7.12.1526 and the Mac 2.11.194 design/feature plan. Status: **open**. DCleaner currently implements a limited native Rust cleaning foundation; it is not a 1:1 replacement yet.

Labels: **observed** = inspected in the original running application; **static** = recovered from authenticated shipped bytes; **implemented** = real DCleaner service exists; **verified** = that particular workflow passed an appropriate test/runtime check. A static route is not a runtime observation. A visible control is not a working feature.

## Windows sections and workflow obligations

| Section | Shipped owners / material states | Original live inspection | DCleaner status |
| --- | --- | --- | --- |
| Health Check | `HealthCheck2`, scan, privacy/space/resolve-issues scan results, step progress, final summary and errors | Welcome and main sidebar observed; other states open | Three-step coordinator and UI are connected in source: explicit start/browser review, exact category/finding selection, cookie settings, staged progress/cancel, reviewed owner plans, outcomes, skip/continue and summary. Eleven coordinator fixture tests pass; full native interaction/effects and final visuals remain unverified. Startup recommendations and Health-level driver/optimizer integration remain open |
| Custom Clean | `CustomClean`, `Welcome`, browser/junk/registry tabs, options, scan and clean progress, cleaning results, close-browser and error dialogs | Navigation input blocked by privilege boundary | Read-only cache scan, file selection, confirmation, system Trash and journal implemented; original categories/rules/privacy/registry parity open |
| Uninstaller | `SoftwareRemover`, scan results, installed/disabled software, remove/disable/enable progress and results, cleanup-period setting | Supplied original capture coverage still incomplete | Native install registration inventory, search/sort/details, reviewed revalidated registered-uninstaller handoff and durable history implemented; 10 backend tests and count-only native read passed. Launch is not uninstall completion. Temporary disable/simulator/expiry/restore and full original workflow remain open |
| Duplicate Finder | Shipped `DiskAnalyzer` drives/folders, options, groups and removal; user-supplied drive/folder capture | Original source selection captured by user | Streaming fingerprint plus exact comparison, source/options selection, current IDs, creation-time keep-oldest/newest, all-copies warning and reviewed Trash cleanup connected; eight fixture tests passed. Rendered/control and original result-state parity still open |
| Cloud Drive Cleaner | `CloudDriveCleaner`, provider/account and external service boundaries | Label observed; page open | Missing; independent provider adapters/authorization required |
| Performance Optimizer | Dashboard, scan/progress, active/sleeping/excluded apps, optimization results and errors | Label observed; page open | Missing |
| Startup Manager | Scan/progress/results; startup apps, context menu, scheduled tasks, Windows services; enable/disable/delete | Original four-tab layout and startup rows supplied by user | Four native inventories, reviewed reversible Run/folder/task/service/static-context changes and recovery connected. Task Scheduler 2.0 COM identity fixed; latest read-only checks found 16 startup entries, 183 tasks, 61 context entries and 295 services (one inaccessible service source). Audient's common-folder HKLM approval state, resolved executable, publisher and version passed a dedicated native check; the native row shows Disabled/Enable. External state refresh, actual local logos and fixed table headers are implemented. Full delete, privileged coverage, real effect interoperability and all-state parity remain open |
| Software Updater | Dashboard, scan/update progress, outdated/up-to-date/skipped-and-ignored tabs, severity/details, update results, reboot/error | Static plus supplied reference composition; live transitions open | Explicit WinGet-source adapter and row review/update/details/skip/ignore flows connected. Real four-column producer output is tested, with 73 real inventory rows read. Exact identity and post-install version verification are required; launch/exit zero is not completion. No real updates executed in QA. Catalogue/severity, full Windows-update/reboot and all-state parity remain open |
| Driver Updater | Scan/update progress, outdated/up-to-date/skipped-and-ignored tabs, details, update results, reboot/error | Label observed; page open | SetupAPI inventory and WUA offers, grouped selection/details, skip/ignore, exact reviewed update/backup/restore, batch stop boundaries and history are connected in source. Twenty-eight driver tests pass, including read-only SetupAPI smoke; native WUA update/restore, post-reboot continuation, cancellation, Fix a problem and final visuals remain open. WUA coverage/version limits do not match the original independent catalogue |
| Settings | General, Menu Layout, Scheduling, Updates, Privacy, My Subscription, About; production reachability of Debug unverified | Label observed; all subpages open | Age/category/theme preferences implemented; all original option parity open |
| Help | Help and external help actions | Label observed; page open | Missing |
| Alternate/conditional sections | Statistics, Ideas Portal, Browser Cleaning, Junk Cleaning, alternate menu routes | Static only; production reachability open | Missing |

## Common state obligations

For each page, inspect and map: initial/returning-user state, available/unsupported/licensed capability state, empty and populated results, search/filter/sort, row/category selection, detail views, progress/cancellation, partial/error results, confirmation, restart/shutdown prompts, persistence after restart, keyboard and accessibility behaviour. Paid reference behaviour must be observed with legitimate access; do not remove the reference's licence checks or manufacture service responses as proof of parity.

## Current foundation evidence

- Rust UI and logic compile on Windows. Eleven core tests passed, including changed-file rejection, unknown IDs before effects, junction/path containment, cancellation, bounded scan, journal intent/receipt failure and settings restart/corruption handling.
- A native debug window was inspected at wide size and a real read-only analysis completed. An explicit isolated native Recycle Bin fixture roundtrip subsequently passed, preserving the durable receipt and restoring only that exact fixture.
- Supported filesystem cleanup roots remain user temp/crash dumps and selected Chrome/Edge/Firefox caches. Selected supported browser history/cookie/download SQLite cleanup and guarded restoration are connected and fixture-verified; actual user browsing databases were not modified during QA. Firefox downloads, passwords, registry, full updater/optimizer/cloud/driver functions remain open. Native application and startup contracts are described above.
- Folder analysis reports largest files; this does not establish Duplicate Finder parity.
- No Mac executable/runtime has been verified. The Mac section below is planning evidence only.

## REA depth and coverage

See the REA evidence section below. REA 6.5.0 and Ghidra 12.1.4 are installed and native decompilation was verified on the current official installer. That proves the provider works, not the application's cleaning algorithm. The installed application has a separate ongoing native analysis.

The broad shipped UI graph completed with resource-limited semantic coverage. Targeted page analyses are required to close those unknowns. An independent static syntax pass parsed all 236 shipped JavaScript files; it supplements REA and does not establish runtime behaviour.

## Completion gate

Every reachable original page/subpage/dialog must have original evidence, a DCleaner owner and real operation, matching option/result semantics, meaningful verification and native visual review. External/privileged operations require their own capability and recovery contract. Keep this ledger open until each obligation is closed. Do not report a percentage based on menu count or present planned controls as completed features.


# REA inspection record

Analysis date: 15 October 2026. REA 6.5.0, Ghidra 12.1.4 and a full Temurin JDK 21 are installed. Artifacts and full analysis outputs remain in ignored local reference storage. Original program/source bytes are not distributed with DCleaner.

## Artifact identity

| Artifact | Identity / role |
| --- | --- |
| Installed `CCleaner.exe` | Windows 7.12.1526.0, native x64, SHA-256 `fd050e99b20e555dbd7a3e47265fddf9202a01eeedd1c0c971ff44374f920ee4`; primary application target |
| Official offline installer | Product 7.12.1526.1963, Gen Digital signature valid, SHA-256 `c730244ff83d8389ae08d48eac6eb3dbeb96ca67b7f4c3a77cd68c69c379f567`; installer evidence only |
| Installed `gui` tree | REA artifact SHA-256 `ab7c068440e5afbae365ada04a8b2c79446fdf546515a42d6aca6188019fdcb4`; compiled Svelte modules hosted in WebView2 |
| Historical portable 6.41 | Separate historical evidence; excluded from current parity assertions |

The host contains a separate native `CCleaner_service.exe` and supporting DLLs. Their functions must be traced separately; the UI executable is not proof of every service algorithm. Runtime settings/licences/databases are outside the shipped-source analysis scope.

## Completed provider proof

The offline installer's actual Ghidra analysis recovered 7,520 procedures, 2,605 defined strings and nine segments. Its entry point at `0x4681a0` was decompiled through the live MCP provider. Evidence `ev_9665e9c65ea700a104c7e9a3c36075b3005c4497b552d81d0251f1fdb287919a` confirms native pseudocode retrieval. It contains installer startup, not CCleaner's cleanup implementation.

## Shipped UI deep analysis

The installed application native overview completed through the CLI: **18,361 procedures, 9,815 defined strings, eight segments**, image base `0x140000000`. Evidence: `ev_82c658e0e5bbe3eb508048d2376281aa2b09ca9d72e673209ac5d2c0e86b7cac`. The native `settings-set` trace also completed: string `0x140531b58`, four recovered containing procedures (`0x1400356f0`, `0x140095d20`, `0x1400a3ee0`, `0x1400a9f40`), evidence `ev_735abaca33a131ccca46ce3bee31c3abbec7bddad33869f759196eb87b86d3fc`. A supported CLI function dossier for `0x1400356f0` completed with pseudocode, assembly, one caller and 36 callees; evidence `ev_e798c91ccdc4af4a05b676ddb6e8d88ba87e1ec2868ba1cd118d2f897ed1770d`. It corroborates native settings/data/window/browser bridge branches. High-level value-flow recovery is truncated and indirect owners remain unresolved; this is not proof of all cleaning/service algorithms. A separate earlier MCP launcher stalled before JVM startup and was stopped; no snapshot defect is established.

The CLI dossier subsequently completed for `0x1400356f0`: evidence `ev_e798c91ccdc4af4a05b676ddb6e8d88ba87e1ec2868ba1cd118d2f897ed1770d`. Ghidra returned pseudocode, assembly, one caller, 36 callees, references, strings and basic blocks. Native branches compare `settings-set`, `persistent-data-set`, `open-browser`, `asyncCall`, `save-accessibility-report`, `close-window`, `window-status-set` and logging levels; settings/data branches extract a value and dispatch through virtual owners. This corroborates the shipped UI bridge contract, not the underlying cleaning or provider algorithms. High p-code value flow is explicitly truncated; indirect callees remain unresolved. Raw proprietary pseudocode stays in ignored private evidence.

Startup verification after the initial snapshot: 12 focused tests passed. A native read-only aggregate check returned startup apps Complete (18), scheduled tasks Complete (183), context menu Complete (61), services Partial (295, one inaccessible source). The scheduler's earlier `E_NOINTERFACE` was traced to using the legacy COM class for `ITaskService`; activation now uses the Task Scheduler 2.0 class. No actual user startup setting was changed in QA.

The full UI graph analyzed 238 relevant files, but semantic admission reached a resource limit. Broad evidence: `ev_690b8370e35ce9d640cc328510853b1b1715838f3e985d4e8665680f3b6f6bee`. Completed graph sealing does not mean complete semantic coverage.

Targeted REA analysis of `StartupManager.js`, `service5.js` and `webview.js` parsed all three selected sources without parse failures (1,612 visited AST nodes and 147 findings). Parent evidence: `ev_48b7dc237190a4ac5d06aed1bb6e0ac5b5d1cd7c757610d4c41f57a7884507f0`. Other files remain explicitly unselected/unknown. Trace evidence `ev_1ae25ab26980866efa10afcc4ca1681e45d8cb66da57408eea9406156ed01580` follows the Startup Manager module across 138 nodes/190 edges, with 40 terminal paths; coverage remains partial and reports no resolved native handoff.

Observed static contract: Startup Manager sends scan, enable/disable with item ID, delete with item ID, get-status and cancel requests. Responses select idle, running, done or error states and drive welcome/progress/results routes. This is a source contract, not evidence that a particular OS startup item was changed.

An independent inert Babel syntax pass parsed all 236 shipped JavaScript files, with no failures, recording per-file hashes/imports/literal routes. It supplements REA's resource-limited graph. `scripts/inspect-shipped-ui.mjs` is analysis tooling only; no reference JavaScript or web runtime ships with DCleaner.

Additional bounded REA profiles completed:

| Profile | Parent Evidence | Selected-source result |
| --- | --- | --- |
| Local feature routers and services | `ev_f3dd5bddb66f93a22cf6b5194aef03eaeb344bb014af6ae2d53fbae26749e79a` | Nine sources, 5,544 AST nodes, 690 findings; no parse failure or semantic truncation within selection |
| Settings and all seven production subpage owners | `ev_41a5ac4d47914ee27723d2d769421a42ea16ae2b0f54098e1530425cb66fe20a` | Nine sources, 21,135 AST nodes, 750 findings; no parse failure or semantic truncation within selection |
| Software/driver updater router and state owners | `ev_983c7338d1d19186cfe63217592fbde08b0bde5110dc60851e3610f1ff0ad31b` | Six sources, 15,024 AST nodes, 617 findings; no parse failure or semantic truncation within selection |
| Browser and junk cleaning page owners, expanded budget | `ev_2773561ce84ffca7eb4ca6a16ba4258a3f8cdbdc5cacb5d175af6b855cff5ab0` | Two sources, 87,088 AST nodes, 277 findings; no parse failure or semantic truncation within selection |
| Custom Clean settings, rule projection and request construction dependencies | `ev_56a806577d9760be9632eb55bd8667f1d93f3add96e2b6ac2ff0950005194bea` | `custom_clean.js`, `rules.js`, `settings2.js`: three parsed sources, 5,748 AST nodes, 139 findings, no parse failure; 235 files unselected and dynamic relationships remain partial |

All these profiles retain partial whole-application coverage because other sources are unselected and dynamic call/object relationships remain unknown. No truncation is not equivalent to complete semantics. The initial combined cleaning profile hit a node ceiling and was superseded for the large page owners by the expanded two-source run.

The dependency pass is inert static analysis, with no app/window launch. Fresh file-version/hash/signature reads still match the recorded installed 7.12.1526 identity. The source constructs selected rule IDs with per-rule active-process handling, typed custom inclusions/exclusions, age-policy substitutions, secure-delete/free-space options and shutdown preference. Rule display grouping is tag-derived, including Windows/System/Applications/Utilities/Multimedia/Store/Downloads/AI/Advanced/Internet and separate browser/registry sets. This is request/configuration evidence, not the underlying rule engine, secure erase, registry repair or shutdown implementation; those effects remain open. Private summary evidence is retained in `reference/rea/ccleaner7-custom-clean-dependencies-summary.json`.

## Native/WebView boundary

The shipped WebView bridge posts typed messages to the native host for service connect/send-message, setting and persistent-data writes, native folder/file selection, path validation, theme, text/CSV export, window state, registry/folder handoff and browser/process coordination. Cleanup, updates and startup changes must be followed from each service request into the native application/service; a bridge message name alone is insufficient.

## Live inspection limitation

The original Health Check welcome and sidebar were captured. CCleaner reports higher Windows integrity than the Computer Use helper; approved navigation clicks do not change the page. Reopening normally did not remove that boundary. The live-page ledger remains open. Static reconstruction and controlled replay, if used, must be labelled separately from live native observations. Do not bypass Windows permission controls or silently count replay states as original execution.

## Remaining deep runs

1. Complete and inspect the installed application's native bridge-handler dossiers using its preserved identity and snapshot.
2. Analyze each page and its direct dependencies in bounded REA source selections, including result/option/modal owners.
3. Trace each service request and resolve relevant native handlers with strings, cross-references and function dossiers. Then inspect the service binary and required DLL boundaries.
4. Reconcile static facts with every reachable live page, conditional licence state and material transition.
5. Map each recovered obligation into independent Rust owners and tests; retain unresolved dynamic edges as gaps.


# DCleaner macOS design and implementation plan

Status: design plan. Native macOS execution, permissions, signing and parity are not yet verified.

Reference target: CCleaner for Mac 2.11.194, the current version reported by the official version history on 15 October 2026. Its feature set differs from Windows; parity is tracked separately.

## Window and navigation

Native titled/resizable macOS window, standard traffic lights at top left, native minimize/full-screen behaviour and 1000x740 starting size. Preserve macOS titlebar/traffic-light hit areas; do not draw Windows controls. The content starts below native chrome. Minimum useful content width is 760px; the 220–270px sidebar contracts to a 92px rail when content needs space. Keyboard focus and active navigation stay stable during reflow.

Sidebar: Overview, Clean Clutter, Browser Cleaner, Find Duplicates, Analyze Photos, Uninstall Apps, Startup Items, History, Settings. Only verified features are enabled in a release; proposed screens carry capability states rather than fake live numbers. The first foundation shares Custom Clean and Disk Analyzer families while broader parity is implemented.

Use the supplied navy screenshot design with blue actions, compact outline controls, dense result tables and a pinned action footer. See DESIGN.md for the sole visual authority.

## Screen journeys

| Screen | Entry and review | Consequential action and recovery |
| --- | --- | --- |
| Overview | Actual eligible bytes, last cleanup, actual recovered space; no synthetic health score | Start read-only analysis |
| Clean Clutter | Category selection, selected permitted roots, real file results, searchable details, disabled ineligible files | Confirm selected current IDs; move to Trash, journal every outcome |
| Browser Cleaner | Installed browsers, profile selection, clear distinctions between cache/cookies/history/passwords; close-browser conflict states | Preserve explicit exclusions; backups/recovery appropriate to each data class |
| Find Duplicates | User-selected folders, content-hash groups, choose one original, show size/path/previews | Prevent cleaning the last retained member; symlink/hard-link treatment is explicit |
| Analyze Photos | User-selected originals, similarity groups and measured quality candidates; decision reasons visible | User chooses removals; no automatic deletion of Photos-library originals |
| Uninstall Apps | Installed app identity, associated-file evidence, protected/current-app exclusions | Review associated files; native uninstall/Trash, reversible where supported |
| Startup Items | Actual login/service entries and current enabled state | Reversible native changes, receipt and restore action |
| History | Confirmed outcome counts, failures, cancelled and uncertain actions separately | Explain restoring via Finder Trash; no unsupported automatic restore claim |
| Settings | Defaults, category exclusions, schedules, theme, permissions | Changing defaults invalidates analysis; enable background effects only after explicit setup |

## File permissions and native platform contracts

Start with user-local eligible directories. Choose broader locations via native folder selection. Model denied, revoked, offline and stale access separately. Explain a Full Disk Access request only for a specific selected capability requiring it; no generic request at launch. If App Sandbox distribution is selected, security-scoped bookmark access must be owned by a native adapter and verified after restart. A saved path string alone is not durable permission.

Use macOS Trash through the platform adapter. Never substitute permanent unlink when Trash fails. Browser data and application databases require appropriate quiescence/backup contracts. Photo-library access and model accuracy are separate from folder scanning. Mac schedules should use approved native launch/login mechanisms and preserve user choices; the Windows scheduler contract is not reused.

## Packaging and acceptance

Build on macOS for Apple Silicon and Intel as required, establish one bundle ID (`com.cocombee.dcleaner`) and a stable Developer ID/signing/notarization path. One canonical installation at `/Applications/DCleaner.app`; persistent data and permission bookmarks live outside the bundle. No signing, notarization or native-install success is claimed from Windows planning.

Acceptance: wide/minimum-size; light/dark; mouse/keyboard/screen reader; loading/empty/populated/failed/cancelled states; native permission grant/deny/revoke; restart with saved settings/history/bookmarks; changed-file and concurrent-action rejection; Trash restoration; update preserving data; all reference parity cases. Automated core tests supplement actual native evidence, not replace it.


# DCleaner

Native Rust desktop cleaner for Windows, with a macOS design plan. The target is functional/section parity with CCleaner Windows 7.12.1526 and a Mac 2.11.194 feature plan, using the user-supplied navy desktop design references and blue actions.

**Work in progress. Full parity is not implemented.** Current working features: bounded read-only temp/browser-cache scanning, per-file selection and review, system Trash cleanup with revalidation and durable intent/outcome history, folder analysis and persistent preferences. See the parity ledger in this plan for unsupported sections and verification gaps.

## Build and run

Requires Rust stable and native platform build tools. On Windows, install Microsoft C++ Build Tools and a Windows SDK, then:

```powershell
./scripts/build.ps1 -Action test
./scripts/build.ps1 -Action build -Release
./scripts/install.ps1 -SourceExecutable ./target/release/dcleaner.exe
```

The canonical Windows executable is `%LOCALAPPDATA%/Programs/DCleaner/DCleaner.exe`, with one Start menu shortcut. The installer replaces that file after checking the build hash and leaves data intact. A session mutex prevents duplicate interactive launches across build paths. Native installation and second-launch checks passed: second launch exited with code 0 and one canonical interactive process remained. This does not establish macOS installation. `cargo run --locked` is a development command; avoid leaving development copies running beside the installed app. `--scan-json` performs a read-only diagnostic scan. Set `DCLEANER_DATA_DIR` only for isolated QA; normal runs use the user's OS application-data directory. References, user data, analysis reports and build output are excluded from Git.

## Plans and evidence

- [Architecture and recovery contracts](ARCHITECTURE.md)
- [Designer contract and attached screenshot references](DESIGN.md)
- [Implementation plan](PLAN.md)
- Mac design and REA evidence are included in this plan.


All application UI and core logic are Rust. Analysis tooling is separate and does not ship as a webview/JavaScript app. DCleaner is an independent implementation; CCleaner reference binaries and proprietary source are not included.
