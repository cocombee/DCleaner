use dcleaner::optimizer_registration::{
    KeyScope, MAX_EXECUTABLE_PATHS, ObservationState, RawKeyRead, RawRegistryValue, RawSubkeyRead,
    ReadBudget, RegistrationReadPort, RegistryValueRole, RegistryView, ReportState,
    ValueValidation, inspect, inspect_with_port,
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

const IFEO_ROOT: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

#[derive(Default)]
struct FixturePort {
    keys: HashMap<(RegistryView, String), RawKeyRead>,
    children: HashMap<(RegistryView, String), RawSubkeyRead>,
    key_reads: Vec<(RegistryView, String, KeyScope)>,
    subkey_reads: Vec<(RegistryView, String)>,
    cancel_after_key_read: bool,
}

impl RegistrationReadPort for FixturePort {
    fn read_key(
        &mut self,
        view: RegistryView,
        key_path: &str,
        scope: KeyScope,
        cancel: &AtomicBool,
        _budget: &mut ReadBudget,
    ) -> RawKeyRead {
        self.key_reads.push((view, key_path.to_owned(), scope));
        let result = self
            .keys
            .get(&(view, key_path.to_owned()))
            .cloned()
            .unwrap_or(RawKeyRead {
                state: ObservationState::Missing,
                values: Vec::new(),
            });
        if self.cancel_after_key_read {
            cancel.store(true, Ordering::Release);
        }
        result
    }

    fn enumerate_direct_subkeys(
        &mut self,
        view: RegistryView,
        key_path: &str,
        _cancel: &AtomicBool,
        _budget: &mut ReadBudget,
    ) -> RawSubkeyRead {
        self.subkey_reads.push((view, key_path.to_owned()));
        self.children
            .get(&(view, key_path.to_owned()))
            .cloned()
            .unwrap_or(RawSubkeyRead {
                state: ObservationState::Complete,
                names: Vec::new(),
            })
    }
}

fn exe(name: &str) -> PathBuf {
    PathBuf::from(format!(r"C:\Tools\{name}"))
}

fn key_path(name: &str) -> String {
    format!("{IFEO_ROOT}\\{name}")
}

fn reg_string(name: &str, kind: u32, value: &str) -> RawRegistryValue {
    RawRegistryValue {
        name: name.into(),
        value_type: kind,
        data: value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect(),
    }
}

fn complete(values: Vec<RawRegistryValue>) -> RawKeyRead {
    RawKeyRead {
        state: ObservationState::Complete,
        values,
    }
}

#[test]
fn retains_raw_root_and_direct_child_values_in_both_views() {
    let executable = exe("sample.exe");
    let root = key_path("sample.exe");
    let mut port = FixturePort::default();
    for view in RegistryView::ALL {
        port.keys.insert(
            (view, root.clone()),
            complete(vec![
                reg_string("Debugger", 1, r"C:\tool\debugger.exe"),
                RawRegistryValue {
                    name: "UseFilter".into(),
                    value_type: 4,
                    data: 1u32.to_le_bytes().to_vec(),
                },
                RawRegistryValue {
                    name: "VendorData".into(),
                    value_type: 3,
                    data: vec![0, 1, 2, 255],
                },
            ]),
        );
        port.children.insert(
            (view, root.clone()),
            RawSubkeyRead {
                state: ObservationState::Complete,
                names: vec!["FilterA".into()],
            },
        );
        port.keys.insert(
            (view, format!("{root}\\FilterA")),
            complete(vec![
                reg_string("FilterFullPath", 2, r"C:\Tools\sample.exe"),
                reg_string("Debugger", 1, r"C:\vendor\watch.exe"),
                RawRegistryValue {
                    name: "Unrelated".into(),
                    value_type: 7,
                    data: vec![9, 8, 7],
                },
            ]),
        );
    }

    let report = inspect_with_port(&[executable], &AtomicBool::new(false), &mut port);
    assert_eq!(report.state, ReportState::Complete);
    assert_eq!(report.executables[0].views.len(), 2);
    for view in &report.executables[0].views {
        assert_eq!(view.root.values.len(), 3);
        let debugger = view
            .root
            .values
            .iter()
            .find(|value| value.name == "Debugger")
            .unwrap();
        assert_eq!(debugger.role, RegistryValueRole::RootDebugger);
        assert_eq!(debugger.value_type, 1);
        assert_eq!(debugger.validation, ValueValidation::WellFormed);
        let use_filter = view
            .root
            .values
            .iter()
            .find(|value| value.name == "UseFilter")
            .unwrap();
        assert_eq!(use_filter.role, RegistryValueRole::RootUseFilter);
        assert_eq!(use_filter.data, 1u32.to_le_bytes().to_vec());
        assert_eq!(use_filter.validation, ValueValidation::WellFormed);
        let vendor = view
            .root
            .values
            .iter()
            .find(|value| value.name == "VendorData")
            .unwrap();
        assert_eq!(vendor.role, RegistryValueRole::Other);
        assert_eq!(vendor.data, vec![0, 1, 2, 255]);

        assert_eq!(view.direct_subkeys.len(), 1);
        let child = &view.direct_subkeys[0];
        assert_eq!(child.name, "FilterA");
        assert_eq!(child.key.values.len(), 3);
        assert!(child.key.values.iter().any(|value| {
            value.name == "FilterFullPath"
                && value.role == RegistryValueRole::FilterFullPath
                && value.value_type == 2
                && value.validation == ValueValidation::WellFormed
        }));
        assert!(
            child.key.values.iter().any(|value| {
                value.name == "Unrelated" && value.role == RegistryValueRole::Other
            })
        );
    }
}

#[test]
fn missing_and_denied_views_remain_distinct() {
    let executable = exe("partial.exe");
    let root = key_path("partial.exe");
    let mut port = FixturePort::default();
    port.keys.insert(
        (RegistryView::Registry64, root),
        RawKeyRead {
            state: ObservationState::Denied { win32_code: 5 },
            values: Vec::new(),
        },
    );

    let report = inspect_with_port(&[executable], &AtomicBool::new(false), &mut port);
    assert_eq!(report.state, ReportState::Partial);
    assert_eq!(
        report.executables[0].views[0].root.state,
        ObservationState::Missing
    );
    assert_eq!(
        report.executables[0].views[1].root.state,
        ObservationState::Denied { win32_code: 5 }
    );
    assert_eq!(
        report.executables[0].state,
        ObservationState::Denied { win32_code: 5 }
    );
    assert_eq!(report.executables[0].views[1].root.values.len(), 0);
}

#[test]
fn malformed_recognized_value_does_not_hide_unrelated_values() {
    let executable = exe("malformed.exe");
    let root = key_path("malformed.exe");
    let mut port = FixturePort::default();
    port.keys.insert(
        (RegistryView::Registry32, root),
        complete(vec![
            RawRegistryValue {
                name: "Debugger".into(),
                value_type: 3,
                data: vec![0, 0, 0, 0],
            },
            RawRegistryValue {
                name: "VendorFlag".into(),
                value_type: 4,
                data: vec![1, 0, 0, 0],
            },
        ]),
    );

    let report = inspect_with_port(&[executable], &AtomicBool::new(false), &mut port);
    assert_eq!(report.state, ReportState::Partial);
    let root = &report.executables[0].views[0].root;
    assert!(matches!(&root.state, ObservationState::Malformed { .. }));
    assert!(matches!(
        &root.values[0].validation,
        ValueValidation::Malformed { .. }
    ));
    assert_eq!(root.values[1].name, "VendorFlag");
    assert_eq!(root.values[1].data, vec![1, 0, 0, 0]);
}

#[test]
fn rejects_non_absolute_paths_without_registry_reads() {
    let mut port = FixturePort::default();
    let report = inspect_with_port(
        &[PathBuf::from("relative\\sample.exe")],
        &AtomicBool::new(false),
        &mut port,
    );
    assert_eq!(report.state, ReportState::Partial);
    assert!(matches!(
        &report.executables[0].state,
        ObservationState::Malformed { .. }
    ));
    assert!(port.key_reads.is_empty());
    assert!(port.subkey_reads.is_empty());
    assert_eq!(report.executables[0].executable, None);
    assert_eq!(report.executables[0].input_index, 0);
}

#[test]
fn overlong_path_is_not_copied_into_the_report() {
    let long_path = format!(
        r"C:\{}\sample.exe",
        "x".repeat(dcleaner::optimizer_registration::MAX_EXECUTABLE_PATH_UTF16_UNITS + 20)
    );
    let mut port = FixturePort::default();
    let report = inspect_with_port(
        &[PathBuf::from(long_path)],
        &AtomicBool::new(false),
        &mut port,
    );
    assert_eq!(report.state, ReportState::Partial);
    assert_eq!(report.executables[0].executable, None);
    assert_eq!(report.executables[0].input_index, 0);
    assert!(matches!(
        &report.executables[0].state,
        ObservationState::Malformed { .. }
    ));
    assert!(port.key_reads.is_empty());
}

#[test]
fn rejects_device_namespaces_ads_wildcards_and_embedded_nul() {
    let paths = [
        PathBuf::from(r"\\.\pipe\sample.exe"),
        PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolume1\sample.exe"),
        PathBuf::from(r"C:\Tools\sample.exe:stream"),
        PathBuf::from(r"C:\Tools\sample?.exe"),
        PathBuf::from("C:\\Tools\\sample\0.exe"),
    ];
    let mut port = FixturePort::default();
    let report = inspect_with_port(&paths, &AtomicBool::new(false), &mut port);
    assert_eq!(report.state, ReportState::Partial);
    assert_eq!(report.executables.len(), paths.len());
    assert!(report.executables.iter().all(|entry| {
        entry.executable.is_none() && matches!(&entry.state, ObservationState::Malformed { .. })
    }));
    assert!(port.key_reads.is_empty());
}

#[test]
fn child_that_disappears_after_enumeration_is_reported_as_partial() {
    let executable = exe("racy.exe");
    let root = key_path("racy.exe");
    let mut port = FixturePort::default();
    port.keys.insert(
        (RegistryView::Registry64, root.clone()),
        complete(Vec::new()),
    );
    port.children.insert(
        (RegistryView::Registry64, root),
        RawSubkeyRead {
            state: ObservationState::Complete,
            names: vec!["Disappeared".into()],
        },
    );

    let report = inspect_with_port(&[executable], &AtomicBool::new(false), &mut port);
    assert_eq!(report.state, ReportState::Partial);
    assert_eq!(
        report.executables[0].views[1].direct_subkeys[0].key.state,
        ObservationState::Failed { win32_code: 2 }
    );
}

#[test]
fn recognized_string_with_interior_nul_is_malformed_and_raw_bytes_survive() {
    let root = key_path("nul.exe");
    let raw_data = "debugger\0unexpected"
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let mut port = FixturePort::default();
    port.keys.insert(
        (RegistryView::Registry32, root),
        complete(vec![RawRegistryValue {
            name: "Debugger".into(),
            value_type: 1,
            data: raw_data.clone(),
        }]),
    );

    let report = inspect_with_port(&[exe("nul.exe")], &AtomicBool::new(false), &mut port);
    let value = &report.executables[0].views[0].root.values[0];
    assert_eq!(report.state, ReportState::Partial);
    assert_eq!(value.data, raw_data);
    assert!(matches!(
        &value.validation,
        ValueValidation::Malformed { .. }
    ));
}

#[test]
fn caps_supplied_paths_and_reports_the_unexamined_remainder() {
    let paths = (0..=MAX_EXECUTABLE_PATHS)
        .map(|index| exe(&format!("app-{index}.exe")))
        .collect::<Vec<_>>();
    let mut port = FixturePort::default();
    let report = inspect_with_port(&paths, &AtomicBool::new(false), &mut port);
    assert_eq!(report.state, ReportState::Limited);
    assert_eq!(report.executables.len(), MAX_EXECUTABLE_PATHS);
    assert_eq!(report.unexamined_path_count, 1);
    assert_eq!(
        port.key_reads.len(),
        MAX_EXECUTABLE_PATHS * RegistryView::ALL.len()
    );
}

#[test]
fn cancellation_is_observed_between_key_and_subkey_reads() {
    let root = key_path("cancel.exe");
    let mut port = FixturePort {
        cancel_after_key_read: true,
        ..FixturePort::default()
    };
    port.keys
        .insert((RegistryView::Registry32, root), complete(Vec::new()));
    let cancel = AtomicBool::new(false);
    let report = inspect_with_port(&[exe("cancel.exe")], &cancel, &mut port);
    assert_eq!(report.state, ReportState::Cancelled);
    assert_eq!(report.executables[0].views.len(), 1);
    assert_eq!(port.key_reads.len(), 1);
    assert!(port.subkey_reads.is_empty());
    assert!(cancel.load(Ordering::Acquire));
}

#[test]
fn limits_direct_subkey_count_without_calling_captured_keys_clear() {
    let executable = exe("many.exe");
    let root = key_path("many.exe");
    let mut port = FixturePort::default();
    port.keys.insert(
        (RegistryView::Registry32, root.clone()),
        complete(Vec::new()),
    );
    port.children.insert(
        (RegistryView::Registry32, root),
        RawSubkeyRead {
            state: ObservationState::Limited {
                reason: "fixture bound".into(),
            },
            names: vec!["Captured".into()],
        },
    );
    port.keys.insert(
        (
            RegistryView::Registry32,
            key_path("many.exe") + r"\Captured",
        ),
        complete(vec![reg_string("Vendor", 1, "visible")]),
    );

    let report = inspect_with_port(&[executable], &AtomicBool::new(false), &mut port);
    assert_eq!(report.state, ReportState::Limited);
    let view = &report.executables[0].views[0];
    assert!(matches!(
        &view.direct_subkeys_state,
        ObservationState::Limited { .. }
    ));
    assert_eq!(view.direct_subkeys.len(), 1);
    assert_eq!(view.direct_subkeys[0].key.values[0].name, "Vendor");
}

#[cfg(windows)]
#[test]
#[ignore = "read-only native IFEO smoke; never writes registry data"]
fn native_read_only_smoke_reports_only_aggregate_counts() {
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .expect("SystemRoot should exist on Windows");
    let candidates = [
        system_root.join(r"System32\cmd.exe"),
        system_root.join(r"System32\notepad.exe"),
    ];
    let paths = candidates
        .into_iter()
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    assert!(
        !paths.is_empty(),
        "expected a known Windows executable path"
    );

    let report = inspect(&paths, &AtomicBool::new(false));
    let view_count = report
        .executables
        .iter()
        .map(|executable| executable.views.len())
        .sum::<usize>();
    let key_count = report
        .executables
        .iter()
        .flat_map(|executable| &executable.views)
        .map(|view| 1 + view.direct_subkeys.len())
        .sum::<usize>();
    let value_count = report
        .executables
        .iter()
        .flat_map(|executable| &executable.views)
        .map(|view| {
            view.root.values.len()
                + view
                    .direct_subkeys
                    .iter()
                    .map(|child| child.key.values.len())
                    .sum::<usize>()
        })
        .sum::<usize>();
    let denied_count = report
        .executables
        .iter()
        .flat_map(|executable| &executable.views)
        .filter(|view| {
            matches!(&view.root.state, ObservationState::Denied { .. })
                || matches!(&view.direct_subkeys_state, ObservationState::Denied { .. })
        })
        .count();
    println!(
        "IFEO read-only smoke: state={:?}, inputs={}, views={}, keys={}, values={}, denied_views={}, unexamined={}",
        report.state,
        paths.len(),
        view_count,
        key_count,
        value_count,
        denied_count,
        report.unexamined_path_count
    );
    assert_eq!(view_count, paths.len() * RegistryView::ALL.len());
}

#[cfg(not(windows))]
#[test]
fn native_entrypoint_is_explicitly_unsupported_off_windows() {
    let report = inspect(&[exe("sample.exe")], &AtomicBool::new(false));
    assert_eq!(report.state, ReportState::Unsupported);
    assert_eq!(report.unexamined_path_count, 1);
    assert!(report.executables.is_empty());
}
