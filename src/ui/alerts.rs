use log::{info, warn, error};
use native_windows_gui as nwg;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub enum AlertType {
    Info,
    Warning,
    Threat,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub alert_type: AlertType,
    pub title: String,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Local>,
}

impl Alert {
    pub fn new(alert_type: AlertType, title: &str, message: &str) -> Self {
        Alert {
            alert_type,
            title: title.to_string(),
            message: message.to_string(),
            timestamp: chrono::Local::now(),
        }
    }
}

#[derive(Default, Clone)]
struct AlertWindowData {
    alerts: Vec<Alert>,
}

#[derive(Default)]
pub struct AlertWindow {
    window: nwg::Window,
    layout: nwg::GridLayout,
    alert_list: nwg::ListView,
    details_label: nwg::Label,
    close_button: nwg::Button,
    clear_button: nwg::Button,
    data: AlertWindowData,
}

impl AlertWindow {
    fn add_alert(&mut self, alert: Alert) {
        // Add to internal list
        self.data.alerts.push(alert.clone());
        
        // Add to list view
        let index = self.alert_list.len() as i32;
        let time_str = alert.timestamp.format("%H:%M:%S").to_string();
        
        let alert_type_str = match alert.alert_type {
            AlertType::Info => "Info",
            AlertType::Warning => "Warning",
            AlertType::Threat => "Threat",
            AlertType::Critical => "Critical",
        };
        
        self.alert_list.insert_item(nwg::InsertListViewItem {
            index,
            column_index: 0,
            text: Some(time_str),
            image: None,
        });
        
        self.alert_list.insert_item(nwg::InsertListViewItem {
            index,
            column_index: 1,
            text: Some(alert_type_str.to_string()),
            image: None,
        });
        
        self.alert_list.insert_item(nwg::InsertListViewItem {
            index,
            column_index: 2,
            text: Some(alert.title),
            image: None,
        });
    }
    
    fn clear_alerts(&mut self) {
        self.data.alerts.clear();
        self.alert_list.clear();
        self.details_label.set_text("");
    }
}

pub fn show_alert_window(alerts: Vec<Alert>) -> Result<(), std::io::Error> {
    nwg::init().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    let mut window = AlertWindow::default();
    
    nwg::Window::builder()
        .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
        .size((600, 400))
        .position((300, 300))
        .title("Security Alerts")
        .build(&mut window.window)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::ListView::builder()
        .parent(&window.window)
        .list_style(nwg::ListViewStyle::Detailed)
        .ex_flags(nwg::ListViewExFlags::GRID | nwg::ListViewExFlags::FULL_ROW_SELECT)
        .build(&mut window.alert_list)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    // Configure columns
    window.alert_list.insert_column(nwg::InsertListViewColumn {
        index: 0,
        fmt: Some(nwg::ListViewColumnFormat::LeftAlign),
        width: Some(80),
        text: Some("Time".to_string()),
    });
    
    window.alert_list.insert_column(nwg::InsertListViewColumn {
        index: 1,
        fmt: Some(nwg::ListViewColumnFormat::LeftAlign),
        width: Some(80),
        text: Some("Type".to_string()),
    });
    
    window.alert_list.insert_column(nwg::InsertListViewColumn {
        index: 2,
        fmt: Some(nwg::ListViewColumnFormat::LeftAlign),
        width: Some(440),
        text: Some("Alert".to_string()),
    });
    
    nwg::Label::builder()
        .parent(&window.window)
        .text("Select an alert to view details")
        .build(&mut window.details_label)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::Button::builder()
        .parent(&window.window)
        .text("Close")
        .build(&mut window.close_button)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::Button::builder()
        .parent(&window.window)
        .text("Clear All")
        .build(&mut window.clear_button)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::GridLayout::builder()
        .parent(&window.window)
        .spacing(1)
        .child(0, 0, 5, 3, Some(&window.alert_list))
        .child(0, 3, 5, 1, Some(&window.details_label))
        .child(3, 4, 1, 1, Some(&window.clear_button))
        .child(4, 4, 1, 1, Some(&window.close_button))
        .build(&mut window.layout)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    // Add alerts
    window.data = AlertWindowData::default();
    for alert in alerts {
        window.add_alert(alert);
    }
    
    // Setup event handlers
    let window_handle = window.window.handle;
    let close_handle = window.close_button.handle;
    let clear_handle = window.clear_button.handle;
    let list_handle = window.alert_list.handle;
    
    let mut window_ref = window;
    
    // Close button event
    nwg::bind_event_handler(&window_ref.window, &window_ref.window, move |evt, _evt_data, _handle| {
        if evt == nwg::Event::OnButtonClick && _handle == close_handle {
            nwg::stop_thread_dispatch();
        } else if evt == nwg::Event::OnButtonClick && _handle == clear_handle {
            window_ref.clear_alerts();
        } else if evt == nwg::Event::OnListViewItemChanged && _handle == list_handle {
            if let Some(item) = window_ref.alert_list.selected_item() {
                if item < window_ref.data.alerts.len() {
                    let alert = &window_ref.data.alerts[item];
                    let details = format!(
                        "Time: {}\nType: {:?}\nTitle: {}\nMessage: {}", 
                        alert.timestamp.format("%Y-%m-%d %H:%M:%S"), 
                        alert.alert_type, 
                        alert.title, 
                        alert.message
                    );
                    window_ref.details_label.set_text(&details);
                }
            }
        } else if evt == nwg::Event::OnWindowClose {
            nwg::stop_thread_dispatch();
        }
    });
    
    nwg::dispatch_thread_events();
    
    Ok(())
}

pub fn show_notification(tray: &nwg::TrayNotification, icon: &nwg::Icon, alert_type: AlertType, message: &str) {
    let title = match alert_type {
        AlertType::Info => "Security Information",
        AlertType::Warning => "Security Warning",
        AlertType::Threat => "Security Threat Detected",
        AlertType::Critical => "CRITICAL SECURITY ALERT",
    };
    
    let flags = match alert_type {
        AlertType::Info => nwg::TrayNotificationFlags::INFO,
        AlertType::Warning => nwg::TrayNotificationFlags::WARNING,
        AlertType::Threat | AlertType::Critical => nwg::TrayNotificationFlags::ERROR,
    };
    
    tray.show(title, message, Some(flags), Some(icon));
    
    // For critical alerts, also log them
    match alert_type {
        AlertType::Info => info!("{}: {}", title, message),
        AlertType::Warning => warn!("{}: {}", title, message),
        AlertType::Threat | AlertType::Critical => error!("{}: {}", title, message),
    }
}

// Global alert history
static mut ALERT_HISTORY: Option<Vec<Alert>> = None;

// Thread-safe access to alert history
fn with_alert_history<F, R>(f: F) -> R
where
    F: FnOnce(&mut Vec<Alert>) -> R,
{
    static INIT: std::sync::Once = std::sync::Once::new();
    
    INIT.call_once(|| {
        unsafe {
            ALERT_HISTORY = Some(Vec::new());
        }
    });
    
    unsafe {
        f(ALERT_HISTORY.as_mut().unwrap())
    }
}

pub fn add_alert(alert_type: AlertType, title: &str, message: &str) {
    let alert = Alert::new(alert_type, title, message);
    with_alert_history(|history| {
        history.push(alert);
    });
}

pub fn get_alerts() -> Vec<Alert> {
    with_alert_history(|history| history.clone())
}

pub fn clear_alerts() {
    with_alert_history(|history| {
        history.clear();
    });
}