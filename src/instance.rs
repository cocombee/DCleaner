//! One interactive DCleaner process per Windows login session, across build paths.
#[cfg(windows)]
mod native {
    use windows::{
        Win32::{
            Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE},
            System::Threading::CreateMutexW,
        },
        core::PCWSTR,
    };
    pub struct Instance(HANDLE);
    impl Drop for Instance {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    pub fn acquire(name: &str) -> windows::core::Result<Option<Instance>> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let handle = CreateMutexW(None, false, PCWSTR(wide.as_ptr()))?;
            let existed = GetLastError() == ERROR_ALREADY_EXISTS;
            let guard = Instance(handle);
            if existed {
                drop(guard);
                Ok(None)
            } else {
                Ok(Some(guard))
            }
        }
    }
    #[cfg(test)]
    mod tests {
        #[test]
        fn second_launch_is_rejected_and_exit_releases_the_instance() {
            let name = format!("Local\\DCleaner-test-{}", uuid::Uuid::new_v4());
            let first = super::acquire(&name).unwrap().unwrap();
            assert!(super::acquire(&name).unwrap().is_none());
            drop(first);
            assert!(super::acquire(&name).unwrap().is_some());
        }
    }
}
#[cfg(windows)]
pub use native::{Instance, acquire};

#[cfg(windows)]
pub fn show_existing() {
    use windows::{
        Win32::UI::WindowsAndMessaging::{
            FindWindowW, SW_RESTORE, SetForegroundWindow, ShowWindow,
        },
        core::w,
    };
    unsafe {
        if let Ok(window) = FindWindowW(None, w!("DCleaner")) {
            let _ = ShowWindow(window, SW_RESTORE);
            let _ = SetForegroundWindow(window);
        }
    }
}
