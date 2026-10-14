# DCleaner

Use Save by default. Follow docs/PLAN.md and docs/ARCHITECTURE.md before extending the app.
The user's product name is DCleaner; UI and services are Rust. Use the supplied screenshot references and Designer skill in docs/DESIGN.md. Audyt and shadcn have been explicitly dropped.
Target feature and behaviour parity with CCleaner Windows 7.12.1526 and Mac 2.11.194; distinguish planned, implemented and verified features. Do not claim 100% parity until the ledger in docs/PLAN.md has evidence for every reachable workflow.
Use the existing plan and architecture files for all functional, REA and Mac documentation. DESIGN.md is the one added design-evidence owner; do not create separate Markdown ledgers or reports.
Keep scanning read-only. Clean only current analysis IDs after review and explicit confirmation. Preserve durable cleanup intent before any filesystem side effect; never retry an uncertain move automatically. Do not add arbitrary recursive deletion.
Keep reference binaries, REA setup/configuration, local file paths, app data and temporary prototypes out of Git. Only change Git state when the user requests the action.
Run cargo test, cargo fmt --check and the appropriate native build before delivery. Verify actual rendered UI; macOS plans are not macOS runtime evidence.
