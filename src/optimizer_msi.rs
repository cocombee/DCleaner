//! Read-only Windows Installer component-key-path evidence for Optimizer.
//!
//! This is one association source, not a complete application file catalogue,
//! publisher trust, exclusive resource ownership, impact or effect authority.
//! In particular the cached base package does not include every transform-added
//! component or every non-key file. Those omissions must remain explicit.
use crate::programs::{InstalledProgram, RegistryHive};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

const MAX_COMPONENTS: usize = 512;
const MAX_TEXT: usize = 4096;
const MAX_NOTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Context {
    Machine,
    UserManaged,
    UserUnmanaged,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentKeyPath {
    pub component: Uuid,
    pub path: PathBuf,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    NotMsi,
    Unavailable,
    Ambiguous,
    Cancelled,
    Inspected,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub status: Status,
    pub product: Option<Uuid>,
    pub context: Option<Context>,
    pub key_paths: Vec<ComponentKeyPath>,
    pub declared_rows_examined: usize,
    pub declared_rows_complete: bool,
    /// Always false for this key-path-only source, even if its row query ends.
    pub covers_all_package_files: bool,
    pub notes: Vec<String>,
}
impl Evidence {
    fn empty(status: Status, product: Option<Uuid>) -> Self {
        Self {
            status,
            product,
            context: None,
            key_paths: Vec::new(),
            declared_rows_examined: 0,
            declared_rows_complete: false,
            covers_all_package_files: false,
            notes: Vec::new(),
        }
    }
    fn note(&mut self, value: impl Into<String>) {
        if self.notes.len() < MAX_NOTES {
            self.notes.push(value.into().chars().take(512).collect());
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Product {
    name: String,
    package: PathBuf,
    transforms: String,
}
struct Rows {
    ids: Vec<String>,
    complete: bool,
}
trait Port {
    fn product(&self, product: Uuid, context: Context) -> Result<Option<Product>, String>;
    fn declared_components(
        &self,
        package: &std::path::Path,
        cancel: &AtomicBool,
    ) -> Result<Rows, String>;
    fn local_key_path(
        &self,
        product: Uuid,
        component: Uuid,
        context: Context,
    ) -> Result<Option<String>, String>;
}

/// Inspect only the selected registration in this process's user/machine
/// context. This never installs, repairs, configures or executes a package.
pub fn inspect(program: &InstalledProgram, cancel: &AtomicBool) -> Evidence {
    #[cfg(windows)]
    {
        inspect_with(program, cancel, &native::WindowsMsi)
    }
    #[cfg(not(windows))]
    {
        let _ = (program, cancel);
        Evidence::empty(Status::Unavailable, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::programs::{ProgramIdentity, RegistrySource, RegistryView};
    use std::{
        cell::{Cell, RefCell},
        collections::HashMap,
    };
    const PRODUCT: &str = "{568082DA-3102-486E-9832-51FC378DF074}";
    fn program(hive: RegistryHive) -> InstalledProgram {
        InstalledProgram {
            identity: ProgramIdentity {
                hive,
                key_name: PRODUCT.into(),
            },
            source: RegistrySource {
                hive,
                view: RegistryView::Registry64,
            },
            display_name: "Fixture Product".into(),
            display_icon: None,
            publisher: None,
            version: None,
            install_location: None,
            install_date: None,
            estimated_size_bytes: None,
            registered_uninstall_command: None,
            uninstall_command: None,
            uninstall_command_error: None,
            system_component: false,
            protected: false,
            no_remove: false,
        }
    }
    struct Fake {
        contexts: Vec<Context>,
        ids: Vec<String>,
        paths: HashMap<Uuid, Result<Option<String>, String>>,
        calls: RefCell<Vec<String>>,
        changing: Cell<bool>,
        reads: Cell<usize>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                contexts: vec![Context::Machine],
                ids: Vec::new(),
                paths: HashMap::new(),
                calls: RefCell::new(Vec::new()),
                changing: Cell::new(false),
                reads: Cell::new(0),
            }
        }
        fn local(&mut self, id: Uuid, path: &str) {
            self.ids.push(id.to_string());
            self.paths.insert(id, Ok(Some(path.into())));
        }
    }
    impl Port for Fake {
        fn product(&self, _: Uuid, c: Context) -> Result<Option<Product>, String> {
            self.calls.borrow_mut().push(format!("product:{c:?}"));
            if !self.contexts.contains(&c) {
                return Ok(None);
            }
            self.reads.set(self.reads.get() + 1);
            Ok(Some(Product {
                name: "Fixture Product".into(),
                package: if self.changing.get() && self.reads.get() > 1 {
                    r"C:\Fixture\changed.msi".into()
                } else {
                    r"C:\Fixture\product.msi".into()
                },
                transforms: "fixture.mst".into(),
            }))
        }
        fn declared_components(&self, _: &std::path::Path, _: &AtomicBool) -> Result<Rows, String> {
            self.calls.borrow_mut().push("rows".into());
            Ok(Rows {
                ids: self.ids.clone(),
                complete: true,
            })
        }
        fn local_key_path(&self, _: Uuid, id: Uuid, c: Context) -> Result<Option<String>, String> {
            self.calls.borrow_mut().push(format!("path:{c:?}:{id}"));
            self.paths.get(&id).cloned().unwrap_or(Ok(None))
        }
    }
    #[test]
    fn registration_context_is_bound_and_keypaths_never_claim_full_file_coverage() {
        let mut fake = Fake::new();
        let id = Uuid::new_v4();
        fake.local(id, r"C:\Fixture\app.exe");
        fake.ids.push(id.to_string().to_uppercase());
        let r = inspect_with(
            &program(RegistryHive::LocalMachine),
            &AtomicBool::new(false),
            &fake,
        );
        assert_eq!(r.status, Status::Inspected);
        assert_eq!(r.context, Some(Context::Machine));
        assert_eq!(r.key_paths.len(), 1);
        assert!(r.declared_rows_complete);
        assert!(!r.covers_all_package_files);
        assert!(r.notes.iter().any(|n| n.contains("transforms")));
        assert!(
            !fake
                .calls
                .borrow()
                .iter()
                .any(|c| c.contains("UserManaged") || c.contains("UserUnmanaged"))
        );
    }
    #[test]
    fn ambiguous_user_contexts_do_not_open_a_cache_or_choose_an_owner() {
        let mut fake = Fake::new();
        fake.contexts = vec![Context::UserManaged, Context::UserUnmanaged];
        let r = inspect_with(
            &program(RegistryHive::CurrentUser),
            &AtomicBool::new(false),
            &fake,
        );
        assert_eq!(r.status, Status::Ambiguous);
        assert!(r.key_paths.is_empty());
        assert!(!fake.calls.borrow().iter().any(|x| x == "rows"));
    }
    #[test]
    fn changed_product_metadata_discards_already_read_associations() {
        let mut fake = Fake::new();
        fake.local(Uuid::new_v4(), r"C:\Fixture\app.exe");
        fake.changing.set(true);
        let r = inspect_with(
            &program(RegistryHive::LocalMachine),
            &AtomicBool::new(false),
            &fake,
        );
        assert_eq!(r.status, Status::Unavailable);
        assert!(r.key_paths.is_empty());
        assert!(!r.declared_rows_complete);
    }
    #[test]
    fn cancellation_invalid_identifiers_and_row_budget_never_silently_complete() {
        let mut fake = Fake::new();
        let r = inspect_with(
            &program(RegistryHive::LocalMachine),
            &AtomicBool::new(true),
            &fake,
        );
        assert_eq!(r.status, Status::Cancelled);
        assert!(fake.calls.borrow().is_empty());
        fake.ids.push("not a GUID".into());
        for index in 0..MAX_COMPONENTS + 1 {
            fake.local(Uuid::from_u128(index as u128 + 1), r"C:\Fixture\app.exe")
        }
        let r = inspect_with(
            &program(RegistryHive::LocalMachine),
            &AtomicBool::new(false),
            &fake,
        );
        assert_eq!(r.declared_rows_examined, MAX_COMPONENTS);
        assert!(!r.declared_rows_complete);
        assert!(r.key_paths.len() < MAX_COMPONENTS);
    }
    #[test]
    fn unsupported_and_nonlocal_paths_cannot_become_file_associations() {
        let mut fake = Fake::new();
        for path in [
            r"\\server\share\app.exe",
            r"02:\Software\Fixture",
            r"relative\app.exe",
            r"C:app.exe",
        ] {
            fake.local(Uuid::new_v4(), path)
        }
        let r = inspect_with(
            &program(RegistryHive::LocalMachine),
            &AtomicBool::new(false),
            &fake,
        );
        assert!(r.key_paths.is_empty());
        assert_eq!(r.status, Status::Inspected);
        assert!(!r.covers_all_package_files);
        let mut p = program(RegistryHive::LocalMachine);
        p.identity.key_name = "ordinary-exe-installer".into();
        fake.calls.borrow_mut().clear();
        assert_eq!(
            inspect_with(&p, &AtomicBool::new(false), &fake).status,
            Status::NotMsi
        );
        assert!(fake.calls.borrow().is_empty());
    }
    #[test]
    #[cfg(windows)]
    #[ignore = "read-only installed Windows Installer metadata; no package actions or installation"]
    fn native_installed_product_component_keypaths_are_read_only_and_bounded() {
        let snapshot = crate::programs::installed_programs().unwrap();
        let cancel = AtomicBool::new(false);
        let mut failures = Vec::new();
        for p in snapshot
            .programs
            .iter()
            .filter(|p| Uuid::parse_str(&p.identity.key_name).is_ok())
            .take(32)
        {
            let evidence = inspect(p, &cancel);
            if evidence.status == Status::Inspected {
                assert!(evidence.declared_rows_examined <= MAX_COMPONENTS);
                assert!(evidence.key_paths.len() <= MAX_COMPONENTS);
                assert!(!evidence.covers_all_package_files);
                println!(
                    "Read-only Installer key-path source: {} declared rows, {} local paths, complete-in-scope={}",
                    evidence.declared_rows_examined,
                    evidence.key_paths.len(),
                    evidence.declared_rows_complete
                );
                return;
            }
            failures.push(evidence.notes.join(" "));
        }
        panic!(
            "No installed product met native fixture preconditions: {}",
            failures.join(" | ")
        );
    }

    #[test]
    fn cancellation_inside_last_native_query_never_publishes_unvalidated_paths() {
        struct CancelInQuery<'a> {
            inner: Fake,
            cancel: &'a AtomicBool,
            at_revalidation: bool,
        }
        impl Port for CancelInQuery<'_> {
            fn product(&self, p: Uuid, c: Context) -> Result<Option<Product>, String> {
                let result = self.inner.product(p, c);
                if self.at_revalidation && self.inner.reads.get() > 1 {
                    self.cancel.store(true, Ordering::Relaxed);
                }
                result
            }
            fn declared_components(
                &self,
                p: &std::path::Path,
                c: &AtomicBool,
            ) -> Result<Rows, String> {
                self.inner.declared_components(p, c)
            }
            fn local_key_path(
                &self,
                p: Uuid,
                id: Uuid,
                c: Context,
            ) -> Result<Option<String>, String> {
                let result = self.inner.local_key_path(p, id, c);
                if !self.at_revalidation {
                    self.cancel.store(true, Ordering::Relaxed);
                }
                result
            }
        }
        for at_revalidation in [false, true] {
            let cancel = AtomicBool::new(false);
            let mut inner = Fake::new();
            inner.local(Uuid::new_v4(), r"C:\Fixture\app.exe");
            let port = CancelInQuery {
                inner,
                cancel: &cancel,
                at_revalidation,
            };
            let result = inspect_with(&program(RegistryHive::LocalMachine), &cancel, &port);
            assert_eq!(result.status, Status::Cancelled);
            assert!(result.key_paths.is_empty());
            assert!(!result.declared_rows_complete);
        }
    }
}

fn inspect_with(program: &InstalledProgram, cancel: &AtomicBool, port: &impl Port) -> Evidence {
    let Ok(product) = Uuid::parse_str(&program.identity.key_name) else {
        return Evidence::empty(Status::NotMsi, None);
    };
    let mut result = Evidence::empty(Status::Unavailable, Some(product));
    if program.identity.hive != program.source.hive || product.is_nil() {
        result.note(
            "The registration identity is inconsistent; no Installer association was inferred.",
        );
        return result;
    }
    if cancel.load(Ordering::Relaxed) {
        result.status = Status::Cancelled;
        return result;
    }
    let contexts: &[Context] = match program.source.hive {
        RegistryHive::LocalMachine => &[Context::Machine],
        RegistryHive::CurrentUser => &[Context::UserManaged, Context::UserUnmanaged],
    };
    let mut matches = Vec::new();
    for &context in contexts {
        if cancel.load(Ordering::Relaxed) {
            result.status = Status::Cancelled;
            return result;
        }
        match port.product(product, context) {
            Ok(Some(info))
                if info
                    .name
                    .trim()
                    .eq_ignore_ascii_case(program.display_name.trim()) =>
            {
                matches.push((context, info))
            }
            Ok(Some(_)) => {
                result.note("Installer's product name does not match this registration.");
                return result;
            }
            Ok(None) => (),
            Err(error) => {
                result.note(error);
                return result;
            }
        }
    }
    if matches.len() > 1 {
        result.status = Status::Ambiguous;
        result.note(
            "This registration matches multiple installation contexts; no context was chosen.",
        );
        return result;
    }
    let Some((context, info)) = matches.pop() else {
        result.note(
            "No installed Windows Installer product matched this registration and account context.",
        );
        return result;
    };
    result.context = Some(context);
    let rows = match port.declared_components(&info.package, cancel) {
        Ok(rows) => rows,
        Err(error) => {
            result.note(error);
            return result;
        }
    };
    let mut seen = HashSet::new();
    result.status = Status::Inspected;
    result.declared_rows_complete = rows.complete && rows.ids.len() <= MAX_COMPONENTS;
    for raw in rows.ids.iter().take(MAX_COMPONENTS) {
        if cancel.load(Ordering::Relaxed) {
            result.status = Status::Cancelled;
            result.declared_rows_complete = false;
            break;
        }
        result.declared_rows_examined += 1;
        let component = match Uuid::parse_str(raw) {
            Ok(id) if !id.is_nil() => id,
            _ => {
                result.declared_rows_complete = false;
                result.note("The cached package contains an invalid component identifier.");
                continue;
            }
        };
        if !seen.insert(component) {
            continue;
        }
        match port.local_key_path(product, component, context) {
            Ok(Some(path)) if local_dos_path(&path) => result.key_paths.push(ComponentKeyPath {
                component,
                path: PathBuf::from(path),
            }),
            Ok(Some(_)) => {
                result.note("A component key path was not a local DOS file path; no file association was made for it.");
            }
            Ok(None) => (),
            Err(error) => {
                result.declared_rows_complete = false;
                result.note(error);
            }
        }
    }
    if !result.declared_rows_complete {
        result.note("The declared component-key-path inspection is incomplete.");
    }
    if !info.transforms.is_empty() {
        result.note("Installed transforms are present. Base-package component enumeration may omit added or changed components.");
    }
    result.note("Installer key paths are metadata references. Non-key files, transform-added components, image identity and exclusive background-resource ownership need separate validation.");
    // A matching GUID is insufficient if the installed product changed while
    // rows were read. Discard all associations on failed/changed revalidation.
    if !cancel.load(Ordering::Relaxed) {
        match port.product(product, context) {
            Ok(Some(current)) if current == info => (),
            _ => {
                result.status = Status::Unavailable;
                result.key_paths.clear();
                result.declared_rows_complete = false;
                result.note("Installer metadata changed or could not be revalidated; associations were discarded.");
            }
        }
    }
    // Cancellation may arrive in the final component or product query, after
    // the loop's last admission check. Do not publish unvalidated references.
    if cancel.load(Ordering::Relaxed) {
        result.status = Status::Cancelled;
        result.key_paths.clear();
        result.declared_rows_complete = false;
    }
    result
}

fn local_dos_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.encode_utf16().count() <= MAX_TEXT
        && !value.contains('\0')
        && bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    };
    use windows::{
        Win32::{
            Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, ERROR_UNKNOWN_PRODUCT},
            Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ},
            System::ApplicationInstallationAndServicing::*,
        },
        core::{PCWSTR, PWSTR},
    };
    const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
    pub(super) struct WindowsMsi;
    struct Handle(MSIHANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                MsiCloseHandle(self.0);
            }
        }
    }
    struct View(Handle);
    impl Drop for View {
        fn drop(&mut self) {
            unsafe {
                MsiViewClose(self.0.0);
            }
        }
    }
    fn wide(value: &str) -> Result<Vec<u16>, String> {
        if value.contains('\0') || value.encode_utf16().count() > MAX_TEXT {
            return Err("Installer text exceeds its inspection bound.".into());
        }
        Ok(value.encode_utf16().chain(Some(0)).collect())
    }
    fn native_context(value: Context) -> MSIINSTALLCONTEXT {
        match value {
            Context::Machine => MSIINSTALLCONTEXT_MACHINE,
            Context::UserManaged => MSIINSTALLCONTEXT_USERMANAGED,
            Context::UserUnmanaged => MSIINSTALLCONTEXT_USERUNMANAGED,
        }
    }
    fn checked(code: u32, operation: &str) -> Result<(), String> {
        if code == ERROR_SUCCESS.0 {
            Ok(())
        } else {
            Err(format!(
                "Installer {operation} failed (Windows code {code})."
            ))
        }
    }
    fn property(product: Uuid, context: Context, name: &str) -> Result<Option<String>, String> {
        let product = wide(&format!("{{{product}}}"))?;
        let name = wide(name)?;
        let mut buffer = vec![0u16; MAX_TEXT + 1];
        let mut length = MAX_TEXT as u32;
        // NULL means this process's user for per-user contexts, and is required
        // for machine context. This inspector never enumerates another account.
        let code = unsafe {
            MsiGetProductInfoExW(
                PCWSTR(product.as_ptr()),
                PCWSTR::null(),
                native_context(context),
                PCWSTR(name.as_ptr()),
                Some(PWSTR(buffer.as_mut_ptr())),
                Some(&mut length),
            )
        };
        if code == ERROR_UNKNOWN_PRODUCT.0 {
            return Ok(None);
        }
        checked(code, "property query")?;
        if length as usize > MAX_TEXT {
            return Err("Installer property exceeds its text bound.".into());
        }
        String::from_utf16(&buffer[..length as usize])
            .map(Some)
            .map_err(|_| "Installer property is not valid UTF-16.".into())
    }
    impl Port for WindowsMsi {
        fn product(&self, product: Uuid, context: Context) -> Result<Option<Product>, String> {
            if property(product, context, "State")?.as_deref() != Some("5") {
                return Ok(None);
            }
            let name = property(product, context, "InstalledProductName")?
                .ok_or("Installed product name is unavailable.")?;
            let package = property(product, context, "LocalPackage")?
                .ok_or("Installed package path is unavailable.")?;
            if !local_dos_path(&package) {
                return Err("The cached Installer package is not a bounded local DOS path.".into());
            }
            let transforms = property(product, context, "Transforms")?.unwrap_or_default();
            Ok(Some(Product {
                name,
                package: package.into(),
                transforms,
            }))
        }
        fn declared_components(&self, package: &Path, cancel: &AtomicBool) -> Result<Rows, String> {
            use std::os::windows::ffi::OsStrExt;
            let package_name: Vec<u16> = package.as_os_str().encode_wide().chain(Some(0)).collect();
            // A retained read-only no-write/no-delete handle pins the leaf
            // while MSI independently opens that same cache path read-only.
            let held = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ.0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(package)
                .map_err(|e| format!("The cached Installer package could not be pinned: {e}"))?;
            let meta = held.metadata().map_err(|e| e.to_string())?;
            if !meta.is_file()
                || meta.file_attributes() & 0x400 != 0
                || meta.len() > MAX_PACKAGE_BYTES
            {
                return Err(
                    "The cached package is redirected, wrong-kind or over its size bound.".into(),
                );
            }
            let mut database = MSIHANDLE::default();
            checked(
                unsafe {
                    MsiOpenDatabaseW(
                        PCWSTR(package_name.as_ptr()),
                        MSIDBOPEN_READONLY,
                        &mut database,
                    )
                },
                "read-only package open",
            )?;
            let database = Handle(database);
            let query =
                wide("SELECT `ComponentId` FROM `Component` WHERE `ComponentId` IS NOT NULL")?;
            let mut view = MSIHANDLE::default();
            checked(
                unsafe { MsiDatabaseOpenViewW(database.0, PCWSTR(query.as_ptr()), &mut view) },
                "component view",
            )?;
            let view = View(Handle(view));
            checked(
                unsafe { MsiViewExecute(view.0.0, MSIHANDLE::default()) },
                "component query",
            )?;
            let mut ids = Vec::new();
            let mut complete = false;
            for _ in 0..=MAX_COMPONENTS {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let mut record = MSIHANDLE::default();
                let code = unsafe { MsiViewFetch(view.0.0, &mut record) };
                if code == ERROR_NO_MORE_ITEMS.0 {
                    complete = true;
                    break;
                }
                checked(code, "component fetch")?;
                let record = Handle(record);
                if ids.len() == MAX_COMPONENTS {
                    break;
                }
                let mut text = [0u16; 65];
                let mut length = 64u32;
                checked(
                    unsafe {
                        MsiRecordGetStringW(
                            record.0,
                            1,
                            Some(PWSTR(text.as_mut_ptr())),
                            Some(&mut length),
                        )
                    },
                    "component identifier",
                )?;
                if length > 64 {
                    return Err("Installer component identifier exceeds its bound.".into());
                }
                ids.push(
                    String::from_utf16(&text[..length as usize])
                        .map_err(|_| "Installer component identifier is not valid UTF-16.")?,
                );
            }
            Ok(Rows { ids, complete })
        }
        fn local_key_path(
            &self,
            product: Uuid,
            component: Uuid,
            context: Context,
        ) -> Result<Option<String>, String> {
            let product = wide(&format!("{{{product}}}"))?;
            let component = wide(&format!("{{{component}}}"))?;
            let mut text = vec![0u16; MAX_TEXT + 1];
            let mut length = MAX_TEXT as u32;
            let state = unsafe {
                MsiGetComponentPathExW(
                    PCWSTR(product.as_ptr()),
                    PCWSTR(component.as_ptr()),
                    PCWSTR::null(),
                    Some(native_context(context)),
                    Some(PWSTR(text.as_mut_ptr())),
                    Some(&mut length),
                )
            };
            if state == INSTALLSTATE_LOCAL {
                if length as usize > MAX_TEXT {
                    return Err("Installer key path exceeds its bound.".into());
                }
                return String::from_utf16(&text[..length as usize])
                    .map(Some)
                    .map_err(|_| "Installer key path is not valid UTF-16.".into());
            }
            if state == INSTALLSTATE_ABSENT
                || state == INSTALLSTATE_UNKNOWN
                || state == INSTALLSTATE_SOURCE
                || state == INSTALLSTATE_NOTUSED
            {
                return Ok(None);
            }
            Err(format!(
                "Installer component path is unavailable (state {}).",
                state.0
            ))
        }
    }
}
