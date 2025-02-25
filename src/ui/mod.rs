pub mod tray;
pub mod alerts;
pub mod logger;

use std::io;
use log::{info, warn, error};
use std::sync::mpsc::Sender;

pub struct UiManager {
    tray_command_sender: Option<Sender<tray::TrayCommand>>,
}

impl UiManager {
    pub fn new() -> Self {
        UiManager {
            tray_command_sender: None,
        }
    }
}

static mut UI_MANAGER: Option<UiManager> = None;

pub fn initialize() -> Result<(), io::Error> {
    info!("Initializing UI components...");
    
    // First, initialize the UI logger
    if let Err(e) = logger::init_ui_logger(log::LevelFilter::Debug) {
        error!("Failed to initialize UI logger: {}", e);
    }
    
    // Initialize system tray
    let tray_sender = match tray::initialize() {
        Ok(sender) => sender,
        Err(e) => {
            error!("Failed to initialize system tray: {}", e);
            return Err(e);
        }
    };
    
    // Store UI manager
    unsafe {
        UI_MANAGER = Some(UiManager {
            tray_command_sender: Some(tray_sender),
        });
    }
    
    Ok(())
}

pub fn show_alert(alert_type: alerts::AlertType, title: &str, message: &str) -> Result<(), io::Error> {
    // Add to alert history
    alerts::add_alert(alert_type, title, message);
    
    // Show notification if we have a tray
    if let Some(sender) = get_tray_sender() {
        tray::show_alert(&sender, alert_type, message.to_string())?;
    }
    
    Ok(())
}

pub fn show_alerts_window() -> Result<(), io::Error> {
    // Get all alerts from history
    let all_alerts = alerts::get_alerts();
    
    // Show alerts window
    alerts::show_alert_window(all_alerts)
}

pub fn show_log_window() -> Result<(), io::Error> {
    logger::show_log_window()
}

pub fn update_status(monitoring_active: bool, protection_active: bool) -> Result<(), io::Error> {
    if let Some(sender) = get_tray_sender() {
        tray::update_status(&sender, monitoring_active, protection_active)?;
    }
    
    Ok(())
}

pub fn update_config(config: crate::agent::config::Config) -> Result<(), io::Error> {
    if let Some(sender) = get_tray_sender() {
        tray::update_config(&sender, config)?;
    }
    
    Ok(())
}

pub fn shutdown() -> Result<(), io::Error> {
    info!("Shutting down UI components...");
    
    // Exit tray
    if let Some(sender) = get_tray_sender() {
        if let Err(e) = tray::exit(&sender) {
            warn!("Error shutting down tray: {}", e);
        }
    }
    
    // Clean up UI manager
    unsafe {
        UI_MANAGER = None;
    }
    
    Ok(())
}

fn get_tray_sender() -> Option<Sender<tray::TrayCommand>> {
    unsafe {
        if let Some(manager) = &UI_MANAGER {
            manager.tray_command_sender.clone()
        } else {
            None
        }
    }
}