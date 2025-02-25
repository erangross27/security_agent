mod agent;
mod monitors;
mod detection;
mod protection;
mod ui;
mod utils;

use log::{info, warn, error, debug};
use std::process;
use std::path::PathBuf;
use std::io;
use std::thread;
use std::time::Duration;

fn main() {
    // Initialize logging
    if let Err(e) = utils::logger::init("info") {
        eprintln!("Failed to initialize logger: {}", e);
        process::exit(1);
    }
    
    info!("Security Agent starting up...");
    
    // Check if running with administrator privileges
    if !utils::is_admin() {
        error!("This application requires administrator privileges to function properly.");
        error!("Please restart the application as administrator.");
        process::exit(1);
    }
    
    // Initialize agent configuration
    let config = match agent::config::load() {
        Ok(config) => {
            info!("Agent configuration loaded successfully");
            config
        },
        Err(e) => {
            error!("Failed to load agent configuration: {}", e);
            info!("Using default configuration");
            agent::config::Config::default()
        }
    };
    
    // Initialize agent services
    match agent::service::initialize() {
        Ok(_) => info!("Agent service initialized successfully"),
        Err(e) => {
            error!("Failed to initialize agent service: {}", e);
            process::exit(1);
        }
    }
    
    // Initialize detection subsystems
    match detection::initialize() {
        Ok(_) => info!("Detection subsystems initialized successfully"),
        Err(e) => {
            error!("Failed to initialize detection subsystems: {}", e);
        }
    }
    
    // Initialize ML detection if models directory exists
    let models_dir = PathBuf::from("models");
    if models_dir.exists() {
        match detection::ml::initialize(&models_dir) {
            Ok(_) => info!("ML detection initialized successfully"),
            Err(e) => {
                warn!("Failed to initialize ML detection: {}", e);
            }
        }
    } else {
        warn!("Models directory not found, ML detection disabled");
        match std::fs::create_dir(&models_dir) {
            Ok(_) => info!("Created models directory for future use"),
            Err(e) => warn!("Failed to create models directory: {}", e),
        }
    }
    
    // Initialize behavior analysis
    match detection::behavior::initialize() {
        Ok(_) => info!("Behavior analysis initialized successfully"),
        Err(e) => {
            warn!("Failed to initialize behavior analysis: {}", e);
        }
    }
    
    // Initialize UI if not running as a service
    if !agent::service::is_running_as_service() {
        match ui::initialize() {
            Ok(_) => info!("User interface initialized"),
            Err(e) => error!("Failed to initialize UI: {}", e)
        }
        
        // Update UI with initial status
        let _ = ui::update_status(false, false);
        let _ = ui::update_config(config.clone());
    }
    
    // Start protection mechanisms
    match protection::start() {
        Ok(_) => {
            info!("Protection mechanisms started successfully");
            if !agent::service::is_running_as_service() {
                let _ = ui::update_status(false, true);
            }
        },
        Err(e) => {
            error!("Failed to start protection mechanisms: {}", e);
        }
    }
    
    // Start the monitoring subsystem based on configuration
    let mut monitors_started = false;
    
    if config.monitoring.enable_process_monitoring || 
       config.monitoring.enable_file_monitoring || 
       config.monitoring.enable_network_monitoring || 
       config.monitoring.enable_browser_monitoring {
        
        match monitors::start() {
            Ok(_) => {
                info!("Monitoring subsystem started successfully");
                monitors_started = true;
                if !agent::service::is_running_as_service() {
                    let _ = ui::update_status(true, true);
                }
            },
            Err(e) => {
                error!("Failed to start monitoring subsystem: {}", e);
            }
        }
    } else {
        info!("All monitors disabled in configuration, not starting monitoring subsystem");
    }
    
    // Show startup notification
    if !agent::service::is_running_as_service() {
        let _ = ui::show_alert(
            ui::alerts::AlertType::Info,
            "Security Agent Started",
            "Security agent is now running and protecting your system."
        );
    }
    
    // Log security event
    utils::logger::security_event(
        "STARTUP",
        "Security agent started successfully",
        "low"
    );
    
    // Enter main event loop
    agent::run();
    
    info!("Security Agent shutting down...");
    
    // Shutdown agent components
    agent::shutdown();
    
    // Stop monitoring subsystem if it was started
    if monitors_started {
        if let Err(e) = monitors::stop() {
            error!("Error stopping monitors: {}", e);
        }
    }
    
    // Stop protection mechanisms
    if let Err(e) = protection::stop() {
        error!("Error stopping protection: {}", e);
    }
    
    // Shutdown UI if not running as a service
    if !agent::service::is_running_as_service() {
        if let Err(e) = ui::shutdown() {
            error!("Error shutting down UI: {}", e);
        }
    }
    
    // Log security event
    utils::logger::security_event(
        "SHUTDOWN",
        "Security agent shut down",
        "low"
    );
    
    info!("Shutdown complete");
}