pub mod service;
pub mod config;

use std::time::Duration;
use log::info;
use crate::monitors;
use crate::protection;
use crate::ui;

pub fn run() {
    // Main event loop
    loop {
        // Process events
        process_events();
        
        // Check if should exit
        if should_exit() {
            break;
        }
        
        // Sleep to prevent CPU spinning
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn process_events() {
    // Process any pending events from monitors
    // This would communicate with the monitor modules
}

fn should_exit() -> bool {
    // Check if the application should exit
    // Could be based on a global flag set by a signal handler
    false
}

pub fn shutdown() {
    // Shutdown agent components
    info!("Shutting down agent subsystems...");
    
    // Stop monitors
    if let Err(e) = monitors::stop() {
        log::error!("Error stopping monitors: {}", e);
    }
    
    // Stop protection
    if let Err(e) = protection::stop() {
        log::error!("Error stopping protection: {}", e);
    }
    
    // Stop UI
    if let Err(e) = ui::shutdown() {
        log::error!("Error shutting down UI: {}", e);
    }
}