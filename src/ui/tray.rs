use log::{info, error, warn};
use native_windows_gui as nwg;
use native_windows_derive::NwgUi;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use std::cell::RefCell;
use std::rc::Rc;
use crate::agent::config;
use crate::ui::alerts;

#[derive(Default)]
pub struct TrayState {
    monitoring_active: bool,
    protection_active: bool,
    config: Option<config::Config>,
}

#[derive(Default, NwgUi)]
pub struct SystemTray {
    #[nwg_control]
    window: nwg::MessageWindow,

    #[nwg_resource(source_file: None)]
    icon: nwg::Icon,

    #[nwg_control]
    #[nwg_events(OnContextMenu: [SystemTray::show_menu], OnMousePress: [SystemTray::show_menu])]
    tray: nwg::TrayNotification,

    #[nwg_control(parent: window, popup: true)]
    tray_menu: nwg::Menu,

    #[nwg_control(parent: tray_menu, text: "Status")]
    status_menu_item: nwg::MenuItem,

    #[nwg_control(parent: tray_menu, text: "Monitoring")]
    monitoring_menu: nwg::Menu,

    #[nwg_control(parent: monitoring_menu, text: "Enable Process Monitoring", check: true)]
    process_monitoring_item: nwg::MenuItem,

    #[nwg_control(parent: monitoring_menu, text: "Enable File Monitoring", check: true)]
    file_monitoring_item: nwg::MenuItem,

    #[nwg_control(parent: monitoring_menu, text: "Enable Network Monitoring", check: true)]
    network_monitoring_item: nwg::MenuItem,

    #[nwg_control(parent: monitoring_menu, text: "Enable Browser Monitoring", check: true)]
    browser_monitoring_item: nwg::MenuItem,

    #[nwg_control(parent: tray_menu, text: "Protection")]
    protection_menu: nwg::Menu,

    #[nwg_control(parent: protection_menu, text: "Block Suspicious Processes", check: true)]
    block_process_item: nwg::MenuItem,

    #[nwg_control(parent: protection_menu, text: "Block Suspicious Network Activity", check: true)]
    block_network_item: nwg::MenuItem,

    #[nwg_control(parent: protection_menu, text: "Prevent Phishing Attacks", check: true)]
    prevent_phishing_item: nwg::MenuItem,

    #[nwg_control(parent: protection_menu, text: "Prevent Social Engineering", check: true)]
    prevent_social_item: nwg::MenuItem,

    #[nwg_control(parent: tray_menu, text: "Open Dashboard")]
    open_dashboard_item: nwg::MenuItem,

    #[nwg_control(parent: tray_menu)]
    tray_menu_sep1: nwg::MenuSeparator,

    #[nwg_control(parent: tray_menu, text: "Exit")]
    exit_item: nwg::MenuItem,

    // Command channel
    #[nwg_data]
    cmd_tx: RefCell<Option<Sender<TrayCommand>>>,
    
    // State
    #[nwg_data]
    state: RefCell<TrayState>,
}

#[derive(Debug)]
pub enum TrayCommand {
    UpdateConfig(config::Config),
    UpdateStatus { monitoring: bool, protection: bool },
    ShowAlert(alerts::AlertType, String),
    Exit,
}

impl SystemTray {
    pub fn show_menu(&self) {
        let (x, y) = nwg::GlobalCursor::position();
        self.tray_menu.popup(x, y);
    }

    fn update_checks(&self) {
        if let Some(config) = &self.state.borrow().config {
            // Update monitoring checkboxes
            self.process_monitoring_item.set_checked(config.monitoring.enable_process_monitoring);
            self.file_monitoring_item.set_checked(config.monitoring.enable_file_monitoring);
            self.network_monitoring_item.set_checked(config.monitoring.enable_network_monitoring);
            self.browser_monitoring_item.set_checked(config.monitoring.enable_browser_monitoring);
            
            // Update protection checkboxes
            self.block_process_item.set_checked(config.protection.block_suspicious_processes);
            self.block_network_item.set_checked(config.protection.block_suspicious_network);
            self.prevent_phishing_item.set_checked(config.protection.prevent_phishing);
            self.prevent_social_item.set_checked(config.protection.prevent_social_engineering);
        }
    }

    fn update_status_text(&self) {
        let state = self.state.borrow();
        let status = match (state.monitoring_active, state.protection_active) {
            (true, true) => "Status: Fully Protected",
            (true, false) => "Status: Monitoring Only",
            (false, true) => "Status: Protection Only",
            (false, false) => "Status: Disabled",
        };
        self.status_menu_item.set_text(status);
    }

    fn exit_application(&self) {
        if let Some(tx) = &*self.cmd_tx.borrow() {
            let _ = tx.send(TrayCommand::Exit);
        }
        nwg::stop_thread_dispatch();
    }
}

pub fn initialize() -> Result<Sender<TrayCommand>, std::io::Error> {
    nwg::init().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    let (ui_tx, ui_rx) = channel();
    let (cmd_tx, cmd_rx) = channel();
    
    // Spawn UI thread
    thread::spawn(move || {
        if let Err(e) = run_ui(ui_rx, cmd_tx) {
            error!("UI thread error: {}", e);
        }
    });
    
    // Wait for UI to be ready
    ui_tx.send(()).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to initialize UI: {}", e)))?;
    
    Ok(cmd_rx)
}

fn run_ui(ui_rx: Receiver<()>, cmd_tx: Sender<TrayCommand>) -> Result<(), Box<dyn std::error::Error>> {
    // Create the UI
    let app = SystemTray::build_ui(Default::default())?;
    
    // Set the tray icon
    app.tray.set_icon(&app.icon);
    app.tray.set_text("Security Agent");
    app.tray.set_visible(true);
    
    // Store command channel
    *app.cmd_tx.borrow_mut() = Some(cmd_tx);
    
    // Handle menu events
    let app_handle = Rc::new(app);
    let event_handle = app_handle.clone();
    
    let handler = move |evt: nwg::Event| {
        match evt {
            nwg::Event::OnMenuItemSelected => {
                if &evt.sender == &event_handle.process_monitoring_item {
                    if let Some(config) = &mut event_handle.state.borrow_mut().config {
                        config.monitoring.enable_process_monitoring = !config.monitoring.enable_process_monitoring;
                        if let Some(tx) = &*event_handle.cmd_tx.borrow() {
                            let _ = tx.send(TrayCommand::UpdateConfig(config.clone()));
                        }
                        event_handle.update_checks();
                    }
                } else if &evt.sender == &event_handle.file_monitoring_item {
                    if let Some(config) = &mut event_handle.state.borrow_mut().config {
                        config.monitoring.enable_file_monitoring = !config.monitoring.enable_file_monitoring;
                        if let Some(tx) = &*event_handle.cmd_tx.borrow() {
                            let _ = tx.send(TrayCommand::UpdateConfig(config.clone()));
                        }
                        event_handle.update_checks();
                    }
                } else if &evt.sender == &event_handle.network_monitoring_item {
                    if let Some(config) = &mut event_handle.state.borrow_mut().config {
                        config.monitoring.enable_network_monitoring = !config.monitoring.enable_network_monitoring;
                        if let Some(tx) = &*event_handle.cmd_tx.borrow() {
                            let _ = tx.send(TrayCommand::UpdateConfig(config.clone()));
                        }
                        event_handle.update_checks();
                    }
                } else if &evt.sender == &event_handle.browser_monitoring_item {
                    if let Some(config) = &mut event_handle.state.borrow_mut().config {
                        config.monitoring.enable_browser_monitoring = !config.monitoring.enable_browser_monitoring;
                        if let Some(tx) = &*event_handle.cmd_tx.borrow() {
                            let _ = tx.send(TrayCommand::UpdateConfig(config.clone()));
                        }
                        event_handle.update_checks();
                    }
                } else if &evt.sender == &event_handle.block_process_item {
                    if let Some(config) = &mut event_handle.state.borrow_mut().config {
                        config.protection.block_suspicious_processes = !config.protection.block_suspicious_processes;
                        if let Some(tx) = &*event_handle.cmd_tx.borrow() {
                            let _ = tx.send(TrayCommand::UpdateConfig(config.clone()));
                        }
                        event_handle.update_checks();
                    }
                } else if &evt.sender == &event_handle.block_network_item {
                    if let Some(config) = &mut event_handle.state.borrow_mut().config {
                        config.protection.block_suspicious_network = !config.protection.block_suspicious_network;
                        if let Some(tx) = &*event_handle.cmd_tx.borrow() {
                            let _ = tx.send(TrayCommand::UpdateConfig(config.clone()));
                        }
                        event_handle.update_checks();
                    }
                } else if &evt.sender == &event_handle.prevent_phishing_item {
                    if let Some(config) = &mut event_handle.state.borrow_mut().config {
                        config.protection.prevent_phishing = !config.protection.prevent_phishing;
                        if let Some(tx) = &*event_handle.cmd_tx.borrow() {
                            let _ = tx.send(TrayCommand::UpdateConfig(config.clone()));
                        }
                        event_handle.update_checks();
                    }
                } else if &evt.sender == &event_handle.prevent_social_item {
                    if let Some(config) = &mut event_handle.state.borrow_mut().config {
                        config.protection.prevent_social_engineering = !config.protection.prevent_social_engineering;
                        if let Some(tx) = &*event_handle.cmd_tx.borrow() {
                            let _ = tx.send(TrayCommand::UpdateConfig(config.clone()));
                        }
                        event_handle.update_checks();
                    }
                } else if &evt.sender == &event_handle.exit_item {
                    event_handle.exit_application();
                }
            }
            _ => {}
        }
    };
    
    // Signal that UI is ready
    ui_rx.recv().expect("Failed to receive UI ready signal");
    
    // Message dispatch loop
    nwg::dispatch_thread_events_with_callback(move || {
        // Process commands
        if let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                TrayCommand::UpdateConfig(cfg) => {
                    app_handle.state.borrow_mut().config = Some(cfg);
                    app_handle.update_checks();
                },
                TrayCommand::UpdateStatus { monitoring, protection } => {
                    app_handle.state.borrow_mut().monitoring_active = monitoring;
                    app_handle.state.borrow_mut().protection_active = protection;
                    app_handle.update_status_text();
                },
                TrayCommand::ShowAlert(alert_type, message) => {
                    alerts::show_notification(&app_handle.tray, &app_handle.icon, alert_type, &message);
                },
                TrayCommand::Exit => {
                    nwg::stop_thread_dispatch();
                }
            }
        }
    });
    
    Ok(())
}

pub fn update_config(tx: &Sender<TrayCommand>, config: config::Config) -> Result<(), std::io::Error> {
    tx.send(TrayCommand::UpdateConfig(config))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to update config: {}", e)))
}

pub fn update_status(tx: &Sender<TrayCommand>, monitoring: bool, protection: bool) -> Result<(), std::io::Error> {
    tx.send(TrayCommand::UpdateStatus { monitoring, protection })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to update status: {}", e)))
}

pub fn show_alert(tx: &Sender<TrayCommand>, alert_type: alerts::AlertType, message: String) -> Result<(), std::io::Error> {
    tx.send(TrayCommand::ShowAlert(alert_type, message))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to show alert: {}", e)))
}

pub fn exit(tx: &Sender<TrayCommand>) -> Result<(), std::io::Error> {
    tx.send(TrayCommand::Exit)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to exit: {}", e)))
}