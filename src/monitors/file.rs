use log::{info, error};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::monitors::MonitorError;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn start() -> Result<(), MonitorError> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(MonitorError::AlreadyRunning);
    }
    
    info!("Starting file system monitoring...");
    // Implement file system monitoring here
    
    Ok(())
}

pub fn stop() -> Result<(), MonitorError> {
    if !RUNNING.swap(false, Ordering::SeqCst) {
        return Err(MonitorError::NotRunning);
    }
    
    info!("Stopping file system monitoring...");
    // Clean up file system monitoring resources
    
    Ok(())
}