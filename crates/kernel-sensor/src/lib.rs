pub mod usb;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEventKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub path: PathBuf,
    pub kind: FileEventKind,
    pub timestamp: u64,
}

/// User-mode directory event sensor that monitors file creation and modification.
pub struct DirectorySensor {
    watch_dir: PathBuf,
    is_running: Arc<AtomicBool>,
    worker_handle: Option<JoinHandle<()>>,
}

impl DirectorySensor {
    pub fn new(watch_dir: PathBuf) -> Self {
        Self {
            watch_dir,
            is_running: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
        }
    }

    /// Starts monitoring the directory on a background thread and dispatches events to callback.
    pub fn start<F>(&mut self, interval: Duration, mut on_event: F)
    where
        F: FnMut(FileEvent) + Send + 'static,
    {
        if self.is_running.load(Ordering::SeqCst) {
            return;
        }

        self.is_running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.is_running);
        let dir = self.watch_dir.clone();

        let handle = thread::spawn(move || {
            let mut snapshot: HashMap<PathBuf, u64> = HashMap::new();

            // Initial snapshot
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let mtime = entry
                            .metadata()
                            .ok()
                            .and_then(|m| m.modified().ok())
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        snapshot.insert(path, mtime);
                    }
                }
            }

            while running.load(Ordering::SeqCst) {
                thread::sleep(interval);

                let mut current: HashMap<PathBuf, u64> = HashMap::new();
                if let Ok(entries) = fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            let mtime = entry
                                .metadata()
                                .ok()
                                .and_then(|m| m.modified().ok())
                                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            current.insert(path.clone(), mtime);

                            let now_secs = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();

                            match snapshot.get(&path) {
                                None => {
                                    on_event(FileEvent {
                                        path,
                                        kind: FileEventKind::Created,
                                        timestamp: now_secs,
                                    });
                                }
                                Some(&old_mtime) if old_mtime != mtime => {
                                    on_event(FileEvent {
                                        path,
                                        kind: FileEventKind::Modified,
                                        timestamp: now_secs,
                                    });
                                }
                                _ => {}
                            }
                        }
                    }
                }

                snapshot = current;
            }
        });

        self.worker_handle = Some(handle);
    }

    /// Stops the background directory sensor.
    pub fn stop(&mut self) {
        self.is_running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for DirectorySensor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn test_directory_sensor_event_detection() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_sensor_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let mut sensor = DirectorySensor::new(temp_dir.clone());
        let (tx, rx) = mpsc::channel();

        sensor.start(Duration::from_millis(30), move |event| {
            let _ = tx.send(event);
        });

        // Small pause to allow sensor to complete baseline snapshot
        thread::sleep(Duration::from_millis(80));

        // Create a new file
        let new_file = temp_dir.join("test_drop.exe");
        fs::write(&new_file, b"test content").unwrap();

        // Wait for event
        let event = rx.recv_timeout(Duration::from_secs(3)).expect("Event timed out");
        assert_eq!(event.kind, FileEventKind::Created);
        assert_eq!(event.path, new_file);

        sensor.stop();
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
