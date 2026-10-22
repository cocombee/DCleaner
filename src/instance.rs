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
    use windows::{Win32::UI::WindowsAndMessaging::FindWindowW, core::w};
    unsafe {
        if let Ok(window) = FindWindowW(None, w!("DCleaner")) {
            request_restore(window);
        }
    }
}

#[cfg(windows)]
fn request_restore(window: windows::Win32::Foundation::HWND) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{SW_RESTORE, ShowWindowAsync};
    // A relaunch must not wait for an unresponsive instance's UI thread.
    // SW_RESTORE already requests activation; do not follow it with a synchronous
    // cross-thread foreground call. Windows retains its normal focus policy.
    unsafe { ShowWindowAsync(window, SW_RESTORE).as_bool() }
}

#[cfg(all(test, windows))]
mod restore_tests {
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    use windows::{
        Win32::{
            Foundation::HWND,
            UI::WindowsAndMessaging::{
                CreateWindowExW, DestroyWindow, HWND_MESSAGE, IsWindowVisible, WINDOW_EX_STYLE,
                WINDOW_STYLE,
            },
        },
        core::w,
    };

    #[test]
    fn restore_does_not_wait_for_an_unresponsive_message_only_owner() {
        let (ready, address) = mpsc::sync_channel(1);
        let (release, blocked) = mpsc::sync_channel(1);
        let owner = thread::spawn(move || unsafe {
            // HWND_MESSAGE has no visible surface or z-order. Never create an
            // ordinary hidden popup here: restoring it would show a real window.
            let window = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("STATIC"),
                w!("DCleaner restore fixture"),
                WINDOW_STYLE::default(),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                None,
                None,
            )
            .unwrap();
            assert!(!IsWindowVisible(window).as_bool());
            ready.send(window.0 as usize).unwrap();
            // No message pump: the target deliberately cannot process restore.
            let _ = blocked.recv_timeout(Duration::from_secs(5));
            assert!(!IsWindowVisible(window).as_bool());
            DestroyWindow(window).unwrap();
        });
        let window = HWND(address.recv_timeout(Duration::from_secs(5)).unwrap() as *mut _);
        let started = Instant::now();
        let queued = super::request_restore(window);
        let elapsed = started.elapsed();
        let _ = release.send(());
        owner.join().unwrap();
        assert!(
            queued,
            "the native asynchronous restore request must be accepted"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "restore waited for the blocked owner: {elapsed:?}"
        );
        eprintln!(
            "ASYNC_RESTORE queued=true elapsed_ms={} message_only=true visible_window=false physical_input=false",
            elapsed.as_millis()
        );
    }
}
