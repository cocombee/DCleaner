use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/brand/windows.rc");
    println!("cargo:rerun-if-changed=assets/brand/dcleaner-dc.ico");
    for name in [
        "WindowsSdkDir",
        "WindowsSDKVersion",
        "WindowsSdkVerBinPath",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "PATH",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let brand_dir = manifest_dir.join("assets").join("brand");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let resource = out_dir.join("dcleaner.res");
    let compiler = find_resource_compiler().unwrap_or_else(|| PathBuf::from("rc.exe"));

    let status = Command::new(&compiler)
        .current_dir(&brand_dir)
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource)
        .arg("windows.rc")
        .status()
        .unwrap_or_else(|error| {
            panic!(
                "failed to run Windows Resource Compiler {}: {error}; install the Windows SDK or add rc.exe to PATH",
                compiler.display()
            )
        });
    if !status.success() {
        panic!("Windows Resource Compiler failed with status {status}");
    }

    println!("cargo:rustc-link-arg-bin=dcleaner={}", resource.display());
}

fn find_resource_compiler() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(path) = env::var_os("WindowsSdkVerBinPath") {
        let path = PathBuf::from(path);
        candidates.push(path.join("x64").join("rc.exe"));
        candidates.push(path.join("rc.exe"));
    }

    if let Some(sdk_dir) = env::var_os("WindowsSdkDir") {
        let sdk_dir = PathBuf::from(sdk_dir);
        if let Some(version) = env::var_os("WindowsSDKVersion") {
            let version_bin = sdk_dir.join("bin").join(version);
            candidates.push(version_bin.join("x64").join("rc.exe"));
        }
        collect_versioned_compilers(&sdk_dir.join("bin"), &mut candidates);
    }

    for variable in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(program_files) = env::var_os(variable) {
            collect_versioned_compilers(
                &PathBuf::from(program_files)
                    .join("Windows Kits")
                    .join("10")
                    .join("bin"),
                &mut candidates,
            );
        }
    }

    candidates.into_iter().find(|path| path.is_file())
}

fn collect_versioned_compilers(bin_dir: &Path, candidates: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(bin_dir) else {
        return;
    };
    let mut version_dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    version_dirs.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
    for version_dir in version_dirs {
        candidates.push(version_dir.join("x64").join("rc.exe"));
        candidates.push(version_dir.join("rc.exe"));
    }
}
