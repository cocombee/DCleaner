# DCleaner design contract

Current authority: the user's supplied screenshots, accepted 15 October 2026, and the user's [Designer skill](https://drive.google.com/file/d/1IrMVEvvV6xizNl_aTHC_KR-5JNYn3F9k/view). The user explicitly dropped Audyt and shadcn. Their styling, geometry and component references no longer govern this app.

The user's selected [anti-slop skill](https://github.com/miqdadbadjuber/anti-slop), core and UI guidance, filters design during the work. The earlier unrelated anti-slop source was rejected and does not govern this app. Reuse this file as the design owner, without new audit Markdown. Reading this as a desktop maintenance app for Windows and Mac users, in the user's navy screenshot language: ENERGY 1 / RHYTHM 1 / MOTION 1. The repeated motif is compact navy maintenance rows with blue inline actions and a fixed selection/action footer. The explicit screenshots authorize this composition; preserve their type hierarchy, meaningful amber findings and labelled progress indicators. The skill filters execution; it does not replace the supplied aesthetic.

Decision reasons: navy/blue follows the user's explicit palette and screenshots; the rail and section pane separate product groups from destinations; Inter regular/semibold follows the compact software reference hierarchy; 28px content insets separate heading, table and footer; elevated panels group actual scan findings; consistent 1.6px line icons identify real maintenance categories. No fabricated metrics, promotional hero, ornamental badges or default template card grid.

Observed correction: the first shell repeated the entire destination list in both columns and wrapped section labels. Wide mode must use a small group/utility icon rail and one compact text section list; constrained mode uses one accessible icon destination list. Each result row needs its genuine contextual controls and review path; a selected-row footer alone is insufficient. Capture and compare the actual page before calling this corrected.

## Attached screenshot references

| Reference | Applied composition |
| --- | --- |
| [Status findings](design/references/01-status-findings.png) | Navy shell, narrow icon rail, adjacent section navigation, title/action header, compact finding cards, real cleanup activity |
| [Disk cleaner](design/references/02-disk-cleaner.png) | Mode selector, dense checkbox table, aligned sizes/counts, ignored rows and pinned action/progress footer |
| [Status cleaning](design/references/03-status-cleaning.png) | Grouped cleanup summary, selected categories, per-row in-progress/completed states and additional findings |
| [App updater](design/references/04-app-updater.png) | Program rows, versions/severity, inline update/download/result states, ignored group and update-all footer |
| [Health summary](design/references/05-health-summary.png) | Three focused circular summaries and direct workflow actions; use measured scan coverage/counts, not invented health percentages |
| [CCleaner section list](design/references/06-ccleaner-sections.png) | Functional navigation authority: every section remains a required implementation obligation |

The first four images own the desktop composition. The health-summary image is a secondary reference for summary instrumentation. The CCleaner sidebar is functional scope evidence. Do not import the reference's placeholder applications, sample metrics, subscription claims, unrelated product sections or branding.

The supplied reference screenshots are third-party reference material, separate from DCleaner's source-code MIT licence.

## Shell and token owners

`src/theme.rs` owns colours, typography, surfaces, controls, row metrics and icon strokes. `src/app.rs` currently owns composition; extract shared shell/result owners as feature coverage grows.

Default appearance: deep navy canvas, darker rail/section navigation, subtly raised navy result surfaces, bright blue primary actions/selection, white headings and slate secondary text. Attention counts use a restrained amber role; success, warning, error and busy states have labelled indicators. Provide a coherent optional light mode. The delivered Rust UI renders the application content rather than the laptop/background decoration in the supplied promotional images.

Wide layout: approximately 64px icon rail, 196px section pane, 28–32px main content inset. Keep utility actions compact and aligned to the title's top edge. Section selection is a low-radius blue bar. Primary/outline actions are compact capsules; tables have restrained divider lines and approximately 44px rows. Result panels use 14–16px corners and subtle background separation. Typography uses Inter regular and actual semibold data, with 22–24px page titles and 12–13px table/control text.

At constrained width the section pane contracts away while the icon rail and accessible section chooser preserve navigation. Tables scroll horizontally when their genuine minimum columns do not fit. Critical selection totals and actions remain visible in a pinned footer. Labels wrap or truncate with a full-text affordance; do not split controls into unreadable fragments.

## Functional section coverage

Required Windows sections: Health Check, Custom Clean, Uninstaller, Duplicate Finder, Cloud Drive Cleaner, Performance Optimizer, Startup Manager, Software Updater, Driver Updater, Settings and Help. Additional conditional sections/subpages remain in PLAN.md. A placeholder or disabled button does not fulfill a section.

Map actual CCleaner functions into the screenshot composition. Custom Clean has browser/junk/registry options and result journeys. Startup Manager has startup apps, context menu, scheduled tasks and Windows services. Software/driver updater pages have outdated, up-to-date, skipped/ignored, details, progress, errors and restart outcomes. Keep each state owned by real services, rather than manufacturing data to fill a screenshot.

## Repeated families and state contracts

| Family | Required structure and states |
| --- | --- |
| Icon rail and section navigation | Consistent 18–20px painted icons, optical stroke, selected/hover/focus/disabled, full accessible names, stable order |
| Finding card | Icon, title/detail group, actual count/value, trailing review action; common vertical alignment and inset |
| Result table | Aligned heading/body columns, sortable data, row and partial category selection, details, filters, empty/partial/error/loading/results; busy/result state in the same row slot |
| Mode/tabs | Compact selected capsule, keyboard navigation and preserved per-tab state; only implemented modes enabled |
| Action footer | Actual selection count and size, current operation state, review/execute/cancel action; stays visible while content scrolls |
| Confirmation/detail dialog | Actual objects/effect, focus/default/cancel, busy lock, exact outcome and uncertain recovery; return focus after close |
| Circular summary | Measured quantity or explicitly unknown state, concise label, direct relevant action; progress arc only when a meaningful denominator exists |
| Activity visualization | Derived only from persisted confirmed outcomes; empty history has an honest empty state, not a sample chart |

## Acceptance

For every original page/subpage/dialog record the functional evidence separately from visual references. Inspect every implemented DCleaner page at 1240×820 and 760×600, default navy and optional light mode, with keyboard focus and relevant empty/populated/loading/error/confirmation states. Compare actual native captures against the attached screenshots for hierarchy, density, insets, component proportions and painted icon/text alignment. Build/test success alone is not visual approval.

The current limited foundation does not close the functional gate. PLAN.md must retain missing or incomplete sections until real operations and verification are present. Scope is not reduced to match the existing five-page prototype.

Native inspection evidence: the debug-only `--render-qa` path exports the actual egui framebuffer, avoiding an occluded desktop capture. It selects a real page, reads actual services and does not manufacture results or execute mutations. The v7 batch captured 44 frames: nine main pages plus browser and Recycle Bin views, both supported sizes and themes. Private populated frames stay in ignored `reference/visual-qa`. Subsequent inspection corrected fixed column geometry, 44px row pitch, stable action/more slots, real metadata, body-only table scrolling, actual detail modals and the navy gradient/capsule controls. Windows now has working app-painted maximize/restore/close controls; macOS retains native window controls. Render export does not prove click-through or effect correctness. Every remaining state remains an open gate.

Application row artwork comes from the actual local `DisplayIcon` registration or resolved executable. Startup, Uninstaller and Software Updater reserve 22px plus an 8px gap within the existing name column. Decode/extraction runs off the UI thread and preserves transparency; missing artwork uses a quiet document outline. Registry strings stay inert, environment expansion is path-only, and network/device/URL/relative/command locators are rejected. Windows native resource extraction passed an executable-icon test; macOS artwork integration remains open. Logos must not substitute for program labels or publisher metadata.

The [native frame index](design/evidence/native-frame-index.json) records the executable and PNG hashes for the v8 44-frame batch. Sixteen empty/read-only Health Check, Custom Clean, Disk Analyzer and History frames are attached beside it, including [navy overview](design/evidence/health-wide-dark-v8.png) and [minimum light layout](design/evidence/disk-minimum-light-v8.png). Populated application, startup, profile, Recycle Bin and Settings captures are retained privately; their absence from Git does not waive their inspection. These are implementation checkpoints, not evidence of pixel-perfect acceptance or complete CCleaner functionality.

The subsequent logo pass adds exact-product MSI artwork discovery when a GUID-keyed installation has no DisplayIcon: read its registered ProductIcon or cached package's component identities, then resolve an installed executable's actual icon. The package is opened read-only; no installer/repair action runs. A native test against the exact 7-Zip registration passed. Program/Software dialogs now pin their title and Close/review actions around a bounded scrolling body; all three application tables instantiate only visible 44px rows. The 44-frame v8 set predates those follow-up corrections, so its hashes must not be presented as their acceptance evidence.

The [follow-up frame index](design/evidence/native-logo-frame-index.json) records the v9 executable and 16 native frames for the four changed pages, at both sizes and themes. Inspection confirms actual Audient/Chrome/Drive/Corsair/Edge artwork in Startup and the registered 7-Zip artwork in both Programs and Software. The latest empty [navy overview](design/evidence/health-wide-dark-v9.png) shows distinct Browser and Software Updater glyphs. The canonical Windows installation was replaced with release SHA-256 `8DEF17865F859F2B1119C6C52D1BDF5BDD8D2D6F7D71F86DDDB40CCE3509B9BF`; debug render hashes are separately recorded and must not be confused with the release binary.

Computed token contrast against current surfaces: dark body 12.84:1, dark muted text 6.80:1, white primary-button text 4.47:1, light muted text 5.37:1. The primary blue matches the supplied artwork; its current small white text is below the 4.5:1 normal-text threshold, so these measurements are not an accessibility pass. Shared buttons/navigation paint an explicit keyboard-focus ring. Every complete screen/state/theme still requires inspection; token checks alone do not pass the delivery gate.
