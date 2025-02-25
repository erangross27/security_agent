use log::{info, warn, error, debug};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use crate::protection::ProtectionSettings;
use crate::ui::alerts;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub struct ProcessProtection {
    active_blocklist: HashSet<String>,
}

impl ProcessProtection {
    pub fn new() -> Self {
        ProcessProtection {
            active_blocklist: HashSet::new(),
        }
    }
    
    pub fn start(&mut self, settings: &ProtectionSettings) -> io::Result<()> {
        if RUNNING.swap(true, Ordering::SeqCst) {
            info!("Process protection already running");
            return Ok(());
        }
        
        info!("Starting process protection...");
        
        // Initialize blocklist from settings
        self.active_blocklist = settings.process_blocklist.clone();
        
        Ok(())
    }
    
    pub fn stop(&mut self) -> io::Result<()> {
        if !RUNNING.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        
        info!("Stopping process protection...");
        
        Ok(())
    }
    
    pub fn update_settings(&mut self, settings: &ProtectionSettings) -> io::Result<()> {
        // Update blocklist
        self.active_blocklist = settings.process_blocklist.clone();
        
        info!("Process protection settings updated");
        Ok(())
    }
    
    pub fn block_process(&self, process_name: &str) -> bool {
        // Check if the process is in the blocklist
        if self.active_blocklist.contains(process_name) {
            warn!("Blocked suspicious process: {}", process_name);
            
            // Generate alert
            alerts::add_alert(
                alerts::AlertType::Threat,
                "Suspicious Process Blocked",
                &format!("Blocked execution of suspicious process: {}", process_name)
            );
            
            return true;
        }
        
        false
    }
    
    pub fn add_to_blocklist(&mut self, process_name: &str) {
        self.active_blocklist.insert(process_name.to_string());
        info!("Added process to blocklist: {}", process_name);
    }
    
    pub fn remove_from_blocklist(&mut self, process_name: &str) {
        if self.active_blocklist.remove(process_name) {
            info!("Removed process from blocklist: {}", process_name);
        }
    }
    
    pub fn get_blocklist(&self) -> HashSet<String> {
        self.active_blocklist.clone()
    }
}