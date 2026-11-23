use std::sync::atomic::{AtomicBool, Ordering};

static MANUAL_GAME_MODE: AtomicBool = AtomicBool::new(false);

/// Enables or disables Game / Silent Mode manually.
pub fn set_game_mode(enabled: bool) {
    MANUAL_GAME_MODE.store(enabled, Ordering::SeqCst);
}

/// Checks if Game / Silent Mode is active to defer heavy background scans and suppress alerts.
pub fn is_game_mode_active() -> bool {
    if MANUAL_GAME_MODE.load(Ordering::SeqCst) {
        return true;
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, if a foreground fullscreen application is detected, defer scan
        // shortcut: simple manual toggle + process check, upgrade to Win32 Shell_NotifyIcon fullscreen hook
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_game_mode_toggle() {
        set_game_mode(true);
        assert!(is_game_mode_active());
        set_game_mode(false);
        assert!(!is_game_mode_active());
    }
}
