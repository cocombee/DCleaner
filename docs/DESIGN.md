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

## Shared geometry correction checkpoint

The user's spacing/corner/button/field/alignment correction is applied through `theme.rs` and its callers. Fields and adjacent field actions are 32px high; fields use an 8px radius with a 10px text inset. The default widget margin had previously been discarded by the custom TextEdit frame, so merely setting a TextEdit margin did not correct painted padding. Labels now enter their 32px row before any child is placed. Selector width measures the longest choice, current value, font, insets and arrow. Checkbox-only styling uses a 3px radius so a neighboring field's 8px radius cannot turn it circular.

| Family | Geometry and evidence |
| --- | --- |
| Main/section navigation | 64px rail and 196px section pane; section selection starts at x76 with text at approximately x84, 30px selection height and 36px pitch. This follows the reference app-interior selection/text anchors at approximately x76/x83; glyph rasterization still needs final installed comparison |
| Fields/selector row | Common 32px visible frame height, measured width, 8px field corners; square checkboxes remain distinct. The 760px Startup frame has aligned field frames and retains all Search/Sort/Descending controls after scrollbar space is reserved |
| Tabs | 28px high capsules with 4px spacing, selected semibold and unselected regular type |
| Table actions | 22px high, 11px radius, separate 22px More control, centered in existing 44px table rows. Header and body columns share their owner widths |
| Finding actions | 28px high, 14px radius; icon, title/detail group, status and action share the measured content-row center |
| Footer actions | 36px high, 18px radius. Footer row height is established before status/selection labels are placed |
| Selection with details | Custom Clean measures title plus wrapped description first, centers its checkbox against that group, and indents both text lines together. Checkbox and text activation remain connected to the same category identity |
| Scrollbars | Reserve their own width instead of covering the final control or summary text. Native v11 frames verify the reserved space; final handle paint changed to foreground-based low opacity after that capture |

The [geometry frame index](design/evidence/native-geometry-frame-index.json) records 44 previously captured actual native frames at both sizes/themes, with corresponding label-free control rectangle/radius JSON hashes. Eight safe empty Health/Custom Clean frames and their layout records are attached, including [navy findings](design/evidence/health-wide-dark-v11.png) and [minimum Custom Clean](design/evidence/clean-minimum-light-v11.png). Populated frames remain private. A rectangle/radius record is useful geometry evidence, not proof of painted glyph alignment, correct operation, all states, or full functional parity.

That geometry-only checkpoint passed 98 ordinary tests, six opt-in native checks excluded, Rust formatting and the native release build. Its uninstalled release SHA-256 was `6574A18481DF10BC6E7FE0F35D065908FEBC5A243A00D83FC53D2AA8BB008E06`. It includes the last scrollbar paint adjustment, so its pixels are not asserted identical to the v11 debug frames. Final installed geometry, dialogs/menus/hover/focus/disabled cases and every missing workflow remain open.

The native export batch opened real application windows and could take focus. The user subsequently prohibited physical desktop actions until confirming one install for inspection. No additional live capture, app launch, mouse/keyboard automation, or installation is authorized before that confirmation; saved-image inspection and background source/tests continue.

Saved-image follow-up inspected all 44 v11 frames across Browser, Custom Clean, Disk Analyzer, Duplicate Finder, Health Check, History, Uninstaller, Recycle Bin, Settings, Software Updater and Startup Manager. The reserved scrollbar edge and Browser header/field-action centerlines are corrected within those views. Two private wide-dark frames (Programs and Startup) contain incidental hover tooltips obscuring rows; they remain incomplete evidence for the obscured content. No new desktop interaction was used for this review, and it does not close menu/hover/focus/effect or final installed acceptance.

Subsequent source integration adds Driver Updater with shared tab/search/table/action owners and a separate chip glyph, plus Health Check's explicit Start, three-step selection/review/progress/outcome workflow. Health starts on the existing finding-card landing view; prerequisite checks and browser review begin only after Start. Its dialogs use the established pinned title/footer and capped natural-height body. The compact icon-rail button also now excludes empty label/grow atoms and uses its own compact inset, preventing the regular labelled button padding from widening one side of the highlight. These new/changed states have **not been rendered or inspected on the installed app**, and the v11 evidence must not be attributed to them.

An offscreen CPU renderer is prepared in debug source to reuse egui layout without opening a native window; its primitive clipping/blending and texture patch tests pass. Automatic approval review rejected the attempted application invocation under the user's no-launch/no-capture restriction, so it did not run and no offscreen application image exists. Its execution, as well as native app inspection and the single install, remains pending the user's confirmation. Software raster output would be separately labelled and would not replace installed/GPU/state acceptance.

The current source checkpoint passes 148 ordinary tests, formatting and the native release build. Current candidate SHA-256 is `4EDB9740D0902E3C1D21C27A369F1F1917184B3D6BDDFD1FE59763A1F8E4EF60`; it supersedes the geometry-only candidate but remains uninstalled and visually unverified for the changes described above. The canonical installation remains the earlier `8DEF...B9BF` build.

Computed token contrast against current surfaces: dark body 12.84:1, dark muted text 6.80:1, white primary-button text 4.47:1, light muted text 5.37:1. The primary blue matches the supplied artwork; its current small white text is below the 4.5:1 normal-text threshold, so these measurements are not an accessibility pass. Shared buttons/navigation paint an explicit keyboard-focus ring. Every complete screen/state/theme still requires inspection; token checks alone do not pass the delivery gate.
