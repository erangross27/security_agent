pub mod process;
pub mod file;
pub mod network;
pub mod browser;

use thiserror::Error;
use std::sync::atomic::{AtomicBool, Ordering};

static MONITORS_RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Monitor already running")]
    AlreadyRunning,
    #[error("Monitor not running")]
    NotRunning,
    #[error("Process monitor error: {0}")]
    ProcessError(String),
    #[error("File monitor error: {0}")]
    FileError(String),
    #[error("Network monitor error: {0}")]
    NetworkError(String),
    #[error("Browser monitor error: {0}")]
    BrowserError(String),
}

pub fn start() -> Result<(), MonitorError> {
    if MONITORS_RUNNING.swap(true, Ordering::SeqCst) {
        return Err(MonitorError::AlreadyRunning);
    }
    
    // Start individual monitors
    process::start()?;
    file::start()?;
    network::start()?;
    browser::start()?;
    
    Ok(())
}

pub fn stop() -> Result<(), MonitorError> {
    if !MONITORS_RUNNING.swap(false, Ordering::SeqCst) {
        return Err(MonitorError::NotRunning);
    }
    
    // Stop monitors in reverse order
    let _ = browser::stop();
    let _ = network::stop();
    let _ = file::stop();
    let _ = process::stop();
    
    Ok(())
}