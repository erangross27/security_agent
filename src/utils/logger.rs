//! Logger utility functions for the security agent.

use log::{info, warn, error, LevelFilter};
use env_logger::{Builder, Env};
use std::io;

/// Initializes the logger with custom formatting and the specified log level.
///
/// # Arguments
///
/// * `level` - The log level to use (debug, info, warn, error)
///
/// # Returns
///
/// * `Result<(), io::Error>` - Success or failure initializing the logger
pub fn init(level: &str) -> Result<(), io::Error> {
    let level_filter = match level.to_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info, // Default to Info if invalid level
    };

    // Create a custom builder with timestamp formatting
    let mut builder = Builder::from_env(Env::default());
    
    builder
        .format_timestamp_secs() // Add timestamps
        .format_module_path(true) // Include module path
        .filter_level(level_filter) // Set log level
        .init();

    info!("Logger initialized at {} level", level);
    
    Ok(())
}

/// Logs a security event with appropriate severity.
///
/// # Arguments
///
/// * `event_type` - Type of security event
/// * `description` - Description of the event
/// * `severity` - Severity level (low, medium, high, critical)
pub fn security_event(event_type: &str, description: &str, severity: &str) {
    match severity.to_lowercase().as_str() {
        "low" => info!("Security Event [{}]: {}", event_type, description),
        "medium" => warn!("Security Event [{}]: {}", event_type, description),
        "high" | "critical" => error!("Security Event [{}]: {}", event_type, description),
        _ => info!("Security Event [{}]: {}", event_type, description),
    }
}