mod agent;
mod monitors;
mod detection;
mod protection;
mod ui;
mod utils;

use log::{info, error};
use std::process;

fn main() {
    // Initialize logging
    env_logger::init();
    
    info!("Security Agent starting up...");
    
    // Check if running with administrator privileges
    if !utils::is_admin() {
        error!("This application requires administrator privileges to function properly.");
        error!("Please restart the application as administrator.");
        process::exit(1);
    }
    
    // Initialize agent services
    match agent::service::initialize() {
        Ok(_) => info!("Agent service initialized successfully"),
        Err(e) => {
            error!("Failed to initialize agent service: {}", e);
            process::exit(1);
        }
    }
    
    // Start the monitoring subsystem
    match monitors::start() {
        Ok(_) => info!("Monitoring subsystem started successfully"),
        Err(e) => {
            error!("Failed to start monitoring subsystem: {}", e);
            process::exit(1);
        }
    }
    
    // Initialize UI if not running as a service
    if !agent::service::is_running_as_service() {
        match ui::initialize() {
            Ok(_) => info!("User interface initialized"),
            Err(e) => error!("Failed to initialize UI: {}", e)
        }
    }
    
    // Enter main event loop
    agent::run();
    
    info!("Security Agent shutting down...");
}