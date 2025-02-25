use log::{info, error};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::monitors::MonitorError;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn start() -> Result<(), MonitorError> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(MonitorError::AlreadyRunning);
    }
    
    info!("Starting network monitoring...");
    // Implement network monitoring here
    
    Ok(())
}

pub fn stop() -> Result<(), MonitorError> {
    if !RUNNING.swap(false, Ordering::SeqCst) {
        return Err(MonitorError::NotRunning);
    }
    
    info!("Stopping network monitoring...");
    // Clean up network monitoring resources
    
    Ok(())
}