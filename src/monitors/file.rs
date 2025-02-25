use log::{info, warn, error, debug};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::thread;
use notify::{Watcher, RecursiveMode, Result as NotifyResult, event::{Event, EventKind}};
use crate::monitors::MonitorError;
use crate::detection::{behavior, ml};
use crate::ui::alerts;

static RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
struct FileEvent {
    path: PathBuf,
    event_type: FileEventType,
    timestamp: Instant,
    process_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed(PathBuf), // To path
    Accessed,
}

struct FileMonitor {
    watched_dirs: Vec<PathBuf>,
    sensitive_exts: HashSet<String>,
    protected_paths: HashSet<PathBuf>,
    events: Vec<FileEvent>,
    max_events: usize,
}

impl FileMonitor {
    fn new() -> Self {
        FileMonitor {
            watched_dirs: Vec::new(),
            sensitive_exts: HashSet::new(),
            protected_paths: HashSet::new(),
            events: Vec::new(),
            max_events: 10000,
        }
    }
    
    fn add_watch_dir(&mut self, dir: PathBuf) {
        if dir.exists() && dir.is_dir() {
            self.watched_dirs.push(dir);
        }
    }
    
    fn add_sensitive_ext(&mut self, ext: &str) {
        self.sensitive_exts.insert(ext.to_lowercase());
    }
    
    fn add_protected_path(&mut self, path: PathBuf) {
        self.protected_paths.insert(path);
    }
    
    fn handle_event(&mut self, event: FileEvent) {
        // Add to our event history
        self.events.push(event.clone());
        
        // Keep event history under max size
        while self.events.len() > self.max_events {
            self.events.remove(0);
        }
        
        // Check for sensitive extensions
        if let Some(ext) = event.path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if self.sensitive_exts.contains(&ext_str) {
                self.handle_sensitive_file_event(&event, &ext_str);
            }
        }
        
        // Check for protected paths
        for protected_path in &self.protected_paths {
            if is_same_path_or_child(&event.path, protected_path) {
                self.handle_protected_path_event(&event, protected_path);
                break;
            }
        }
        
        // Generate behavior event
        self.generate_behavior_event(&event);
        
        // Run ML analysis if the file was created or modified
        if matches!(event.event_type, FileEventType::Created | FileEventType::Modified) {
            self.run_ml_analysis(&event);
        }
    }
    
    fn handle_sensitive_file_event(&self, event: &FileEvent, ext: &str) {
        let path_str = event.path.to_string_lossy();
        
        match event.event_type {
            FileEventType::Created => {
                warn!("Sensitive file created: {} (ext: {})", path_str, ext);
                
                alerts::add_alert(
                    alerts::AlertType::Warning,
                    "Sensitive File Created",
                    &format!("A file with sensitive extension '.{}' was created: {}", ext, path_str)
                );
            },
            FileEventType::Modified => {
                debug!("Sensitive file modified: {} (ext: {})", path_str, ext);
            },
            FileEventType::Deleted => {
                warn!("Sensitive file deleted: {} (ext: {})", path_str, ext);
                
                alerts::add_alert(
                    alerts::AlertType::Warning,
                    "Sensitive File Deleted",
                    &format!("A file with sensitive extension '.{}' was deleted: {}", ext, path_str)
                );
            },
            FileEventType::Renamed(to_path) => {
                warn!("Sensitive file renamed: {} -> {} (ext: {})", path_str, to_path.to_string_lossy(), ext);
                
                alerts::add_alert(
                    alerts::AlertType::Info,
                    "Sensitive File Renamed",
                    &format!("A file with sensitive extension '.{}' was renamed: {} -> {}", 
                             ext, path_str, to_path.to_string_lossy())
                );
            },
            FileEventType::Accessed => {
                debug!("Sensitive file accessed: {} (ext: {})", path_str, ext);
            },
        }
    }
    
    fn handle_protected_path_event(&self, event: &FileEvent, protected_path: &Path) {
        let path_str = event.path.to_string_lossy();
        let protected_path_str = protected_path.to_string_lossy();
        
        match event.event_type {
            FileEventType::Created => {
                warn!("File created in protected path: {} (protected: {})", path_str, protected_path_str);
                
                alerts::add_alert(
                    alerts::AlertType::Warning,
                    "Protected Path Modified",
                    &format!("A file was created in protected path '{}': {}", protected_path_str, path_str)
                );
            },
            FileEventType::Modified => {
                warn!("File modified in protected path: {} (protected: {})", path_str, protected_path_str);
                
                alerts::add_alert(
                    alerts::AlertType::Warning,
                    "Protected Path Modified",
                    &format!("A file was modified in protected path '{}': {}", protected_path_str, path_str)
                );
            },
            FileEventType::Deleted => {
                warn!("File deleted from protected path: {} (protected: {})", path_str, protected_path_str);
                
                alerts::add_alert(
                    alerts::AlertType::Threat,
                    "Protected Path Modified",
                    &format!("A file was deleted from protected path '{}': {}", protected_path_str, path_str)
                );
            },
            FileEventType::Renamed(_) => {
                warn!("File renamed in protected path: {} (protected: {})", path_str, protected_path_str);
                
                alerts::add_alert(
                    alerts::AlertType::Warning,
                    "Protected Path Modified",
                    &format!("A file was renamed in protected path '{}': {}", protected_path_str, path_str)
                );
            },
            FileEventType::Accessed => {
                debug!("File accessed in protected path: {} (protected: {})", path_str, protected_path_str);
            },
        }
    }
    
    fn generate_behavior_event(&self, event: &FileEvent) {
        let event_type = match event.event_type {
            FileEventType::Created => behavior::EventType::FileCreated,
            FileEventType::Modified => behavior::EventType::FileModified,
            FileEventType::Deleted => behavior::EventType::FileDeleted,
            FileEventType::Renamed(_) => behavior::EventType::FileModified,
            FileEventType::Accessed => return, // Skip accessed events for behavior analysis
        };
        
        let path_str = event.path.to_string_lossy().to_string();
        
        let mut details = HashMap::new();
        details.insert("path".to_string(), path_str.clone());
        
        if let Some(pid) = event.process_id {
            details.insert("process_id".to_string(), pid.to_string());
        }
        
        if let Some(ext) = event.path.extension() {
            details.insert("extension".to_string(), ext.to_string_lossy().to_string());
        }
        
        if let FileEventType::Renamed(to_path) = &event.event_type {
            details.insert("to_path".to_string(), to_path.to_string_lossy().to_string());
        }
        
        let _ = behavior::process_event(behavior::Event::new(
            event_type,
            &path_str,
            None,
            details
        ));
    }
    
    fn run_ml_analysis(&self, event: &FileEvent) {
        // Only analyze files, not directories
        if !event.path.is_file() {
            return;
        }
        
        let path_str = event.path.to_string_lossy().to_string();
        
        // Extract features and run ML prediction
        match ml::extract_file_features(&path_str) {
            Ok(features) => {
                if let Ok(prediction) = ml::predict_file(&path_str, features) {
                    if prediction.is_malicious {
                        warn!(
                            "ML detection for file '{}': {} ({:.2}% confidence)",
                            path_str,
                            prediction.label,
                            prediction.confidence * 100.0
                        );
                    }
                }
            },
            Err(e) => error!("Failed to extract file features: {}", e),
        }
    }
    
    fn get_recent_events(&self, limit: usize) -> Vec<FileEvent> {
        let start = if self.events.len() > limit {
            self.events.len() - limit
        } else {
            0
        };
        
        self.events[start..].to_vec()
    }
}

// Helper function to check if a path is the same as or a child of another path
fn is_same_path_or_child(path: &Path, parent: &Path) -> bool {
    if path == parent {
        return true;
    }
    
    match path.strip_prefix(parent) {
        Ok(_) => true,
        Err(_) => false,
    }
}

// Global monitor instance
static MONITOR: Mutex<Option<FileMonitor>> = Mutex::new(None);

pub fn start() -> Result<(), MonitorError> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(MonitorError::AlreadyRunning);
    }
    
    info!("Starting file system monitoring...");
    
    // Initialize monitor
    let mut monitor = FileMonitor::new();
    
    // Add default watch directories
    if cfg!(target_os = "windows") {
        // Windows default watch directories
        monitor.add_watch_dir(PathBuf::from("C:\\Windows\\System32"));
        monitor.add_watch_dir(PathBuf::from("C:\\Program Files"));
        monitor.add_watch_dir(PathBuf::from("C:\\Program Files (x86)"));
        monitor.add_watch_dir(PathBuf::from("C:\\Users"));
    } else if cfg!(target_os = "linux") {
        // Linux default watch directories
        monitor.add_watch_dir(PathBuf::from("/etc"));
        monitor.add_watch_dir(PathBuf::from("/bin"));
        monitor.add_watch_dir(PathBuf::from("/usr/bin"));
        monitor.add_watch_dir(PathBuf::from("/home"));
    } else if cfg!(target_os = "macos") {
        // macOS default watch directories
        monitor.add_watch_dir(PathBuf::from("/Applications"));
        monitor.add_watch_dir(PathBuf::from("/Users"));
        monitor.add_watch_dir(PathBuf::from("/System/Library"));
    }
    
    // Add default sensitive extensions
    for ext in &["exe", "dll", "sys", "bat", "ps1", "vbs", "js", "cmd"] {
        monitor.add_sensitive_ext(ext);
    }
    
    // Add default protected paths
    if cfg!(target_os = "windows") {
        monitor.add_protected_path(PathBuf::from("C:\\Windows\\System32\\drivers"));
        monitor.add_protected_path(PathBuf::from("C:\\Windows\\SysWOW64"));
    } else if cfg!(target_os = "linux") {
        monitor.add_protected_path(PathBuf::from("/etc/passwd"));
        monitor.add_protected_path(PathBuf::from("/etc/shadow"));
        monitor.add_protected_path(PathBuf::from("/etc/sudoers"));
    }
    
    // Store the monitor
    {
        let mut guard = MONITOR.lock().unwrap();
        *guard = Some(monitor);
    }
    
    // Start the file watcher thread
    thread::spawn(|| {
        file_watcher_thread();
    });
    
    Ok(())
}

fn file_watcher_thread() {
    use notify::{Config, RecommendedWatcher, EventHandler};
    use std::sync::mpsc;
    
    struct FileEventHandler {
        tx: mpsc::Sender<FileEvent>,
    }
    
    impl EventHandler for FileEventHandler {
        fn handle_event(&mut self, event: notify::Result<Event>) {
            match event {
                Ok(event) => {
                    for path in event.paths {
                        let event_type = match event.kind {
                            EventKind::Create(_) => FileEventType::Created,
                            EventKind::Modify(_) => FileEventType::Modified,
                            EventKind::Remove(_) => FileEventType::Deleted,
                            EventKind::Access(_) => FileEventType::Accessed,
                            EventKind::Other => continue,
                        };
                        
                        let file_event = FileEvent {
                            path,
                            event_type,
                            timestamp: Instant::now(),
                            process_id: None, // Not available from this API
                        };
                        
                        let _ = self.tx.send(file_event);
                    }
                },
                Err(e) => error!("File watch error: {}", e),
            }
        }
    }
    
    // Create the channel for events
    let (tx, rx) = mpsc::channel();
    let event_handler = FileEventHandler { tx };
    
    // Get watch directories
    let watch_dirs = {
        let guard = MONITOR.lock().unwrap();
        if let Some(monitor) = &*guard {
            monitor.watched_dirs.clone()
        } else {
            return;
        }
    };
    
    // Create the watcher
    let mut watcher = match RecommendedWatcher::new(event_handler, Config::default()) {
        Ok(watcher) => watcher,
        Err(e) => {
            error!("Failed to create file watcher: {}", e);
            return;
        }
    };
    
    // Add watch directories
    for dir in watch_dirs {
        if let Err(e) = watcher.watch(&dir, RecursiveMode::Recursive) {
            error!("Failed to watch directory {}: {}", dir.display(), e);
        } else {
            info!("Watching directory: {}", dir.display());
        }
    }
    
    // Process events
    while RUNNING.load(Ordering::SeqCst) {
        if let Ok(event) = rx.recv_timeout(Duration::from_secs(1)) {
            // Get the monitor
            let mut guard = match MONITOR.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to acquire file monitor lock: {}", e);
                    continue;
                }
            };
            
            let monitor = match &mut *guard {
                Some(monitor) => monitor,
                None => {
                    error!("File monitor not initialized");
                    continue;
                }
            };
            
            // Handle the event
            monitor.handle_event(event);
        }
    }
    
    info!("File monitoring thread exited");
}

pub fn stop() -> Result<(), MonitorError> {
    if !RUNNING.swap(false, Ordering::SeqCst) {
        return Err(MonitorError::NotRunning);
    }
    
    info!("Stopping file system monitoring...");
    
    // Clear the monitor
    let mut guard = MONITOR.lock().unwrap();
    *guard = None;
    
    Ok(())
}

pub fn add_watch_dir(dir: PathBuf) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_watch_dir(dir);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn add_sensitive_ext(ext: &str) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_sensitive_ext(ext);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn add_protected_path(path: PathBuf) -> Result<(), MonitorError> {
    let mut guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &mut *guard {
        monitor.add_protected_path(path);
        Ok(())
    } else {
        Err(MonitorError::NotRunning)
    }
}

pub fn get_recent_events(limit: usize) -> Result<Vec<(String, String, String)>, MonitorError> {
    let guard = MONITOR.lock().unwrap();
    
    if let Some(monitor) = &*guard {
        let events = monitor.get_recent_events(limit);
        
        let mut result = Vec::new();
        for event in events {
            let event_type = match event.event_type {
                FileEventType::Created => "Created".to_string(),
                FileEventType::Modified => "Modified".to_string(),
                FileEventType::Deleted => "Deleted".to_string(),
                FileEventType::Renamed(to_path) => format!("Renamed to {}", to_path.to_string_lossy()),
                FileEventType::Accessed => "Accessed".to_string(),
            };
            
            let timestamp = format!("{:?}", event.timestamp);
            let path = event.path.to_string_lossy().to_string();
            
            result.push((timestamp, event_type, path));
        }
        
        Ok(result)
    } else {
        Err(MonitorError::NotRunning)
    }
}