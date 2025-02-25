use log::{info, warn, error, debug};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use crate::protection::ProtectionSettings;
use crate::ui::alerts;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub struct FileProtection {
    active_extension_blocklist: HashSet<String>,
    protected_paths: HashSet<PathBuf>,
}

impl FileProtection {
    pub fn new() -> Self {
        let mut protected_paths = HashSet::new();
        
        // Add default protected paths
        if cfg!(target_os = "windows") {
            protected_paths.insert(PathBuf::from("C:\\Windows\\System32"));
            protected_paths.insert(PathBuf::from("C:\\Windows\\System"));
        } else if cfg!(target_os = "linux") {
            protected_paths.insert(PathBuf::from("/etc"));
            protected_paths.insert(PathBuf::from("/bin"));
            protected_paths.insert(PathBuf::from("/sbin"));
        } else if cfg!(target_os = "macos") {
            protected_paths.insert(PathBuf::from("/System"));
            protected_paths.insert(PathBuf::from("/usr/bin"));
        }
        
        FileProtection {
            active_extension_blocklist: HashSet::new(),
            protected_paths,
        }
    }
    
    pub fn start(&mut self, settings: &ProtectionSettings) -> io::Result<()> {
        if RUNNING.swap(true, Ordering::SeqCst) {
            info!("File protection already running");
            return Ok(());
        }
        
        info!("Starting file protection...");
        
        // Initialize extension blocklist from settings
        self.active_extension_blocklist = settings.file_extension_blocklist.clone();
        
        Ok(())
    }
    
    pub fn stop(&mut self) -> io::Result<()> {
        if !RUNNING.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        
        info!("Stopping file protection...");
        
        Ok(())
    }
    
    pub fn update_settings(&mut self, settings: &ProtectionSettings) -> io::Result<()> {
        // Update extension blocklist
        self.active_extension_blocklist = settings.file_extension_blocklist.clone();
        
        info!("File protection settings updated");
        Ok(())
    }
    
    pub fn block_file_access(&self, path: &Path, action: FileAction) -> bool {
        // Check if the file has a blocked extension
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if self.active_extension_blocklist.contains(&ext_str) {
                let action_str = match action {
                    FileAction::Create => "create",
                    FileAction::Modify => "modify",
                    FileAction::Delete => "delete",
                    FileAction::Execute => "execute",
                };
                
                warn!("Blocked {} of file with suspicious extension: {}", action_str, path.display());
                
                // Generate alert
                alerts::add_alert(
                    alerts::AlertType::Threat,
                    "Suspicious File Access Blocked",
                    &format!("Blocked attempt to {} file with suspicious extension: {}", action_str, path.display())
                );
                
                return true;
            }
        }
        
        // Check if the file is in a protected path
        for protected_path in &self.protected_paths {
            if is_same_path_or_child(path, protected_path) {
                // Only block modifications and deletions in protected paths
                if matches!(action, FileAction::Modify | FileAction::Delete) {
                    let action_str = match action {
                        FileAction::Modify => "modify",
                        FileAction::Delete => "delete",
                        _ => unreachable!(),
                    };
                    
                    warn!("Blocked {} of file in protected path: {}", action_str, path.display());
                    
                    // Generate alert
                    alerts::add_alert(
                        alerts::AlertType::Threat,
                        "Protected File Access Blocked",
                        &format!("Blocked attempt to {} file in protected path: {}", action_str, path.display())
                    );
                    
                    return true;
                }
            }
        }
        
        false
    }
    
    pub fn add_to_extension_blocklist(&mut self, ext: &str) {
        let ext_lower = ext.to_lowercase();
        self.active_extension_blocklist.insert(ext_lower);
        info!("Added extension to blocklist: {}", ext);
    }
    
    pub fn add_protected_path(&mut self, path: PathBuf) {
        self.protected_paths.insert(path.clone());
        info!("Added protected path: {}", path.display());
    }
    
    pub fn remove_from_extension_blocklist(&mut self, ext: &str) {
        let ext_lower = ext.to_lowercase();
        if self.active_extension_blocklist.remove(&ext_lower) {
            info!("Removed extension from blocklist: {}", ext);
        }
    }
    
    pub fn remove_protected_path(&mut self, path: &Path) {
        if self.protected_paths.remove(path) {
            info!("Removed protected path: {}", path.display());
        }
    }
    
    pub fn get_extension_blocklist(&self) -> HashSet<String> {
        self.active_extension_blocklist.clone()
    }
    
    pub fn get_protected_paths(&self) -> HashSet<PathBuf> {
        self.protected_paths.clone()
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

pub enum FileAction {
    Create,
    Modify,
    Delete,
    Execute,
}