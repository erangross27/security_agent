use log::{Record, Level, Metadata, LevelFilter, SetLoggerError};
use native_windows_gui as nwg;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::VecDeque;
use chrono::Local;

const MAX_LOG_ENTRIES: usize = 1000;

struct UiLogger {
    tx: Arc<Mutex<Option<Sender<LogEntry>>>>,
    min_level: Level,
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Local>,
    pub level: Level,
    pub target: String,
    pub message: String,
}

impl log::Log for UiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.min_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let entry = LogEntry {
                timestamp: Local::now(),
                level: record.level(),
                target: record.target().to_string(),
                message: format!("{}", record.args()),
            };
            
            if let Ok(guard) = self.tx.lock() {
                if let Some(tx) = &*guard {
                    let _ = tx.send(entry);
                }
            }
        }
    }

    fn flush(&self) {}
}

static LOGGER: UiLogger = UiLogger {
    tx: Arc::new(Mutex::new(None)),
    min_level: Level::Info,
};

#[derive(Default)]
struct LogWindowData {
    log_entries: VecDeque<LogEntry>,
    auto_scroll: bool,
    filter_level: Level,
    filter_text: String,
}

#[derive(Default)]
pub struct LogWindow {
    window: nwg::Window,
    layout: nwg::GridLayout,
    log_list: nwg::ListView,
    level_combo: nwg::ComboBox<&'static str>,
    filter_input: nwg::TextInput,
    filter_button: nwg::Button,
    auto_scroll_check: nwg::CheckBox,
    clear_button: nwg::Button,
    close_button: nwg::Button,
    data: LogWindowData,
}

impl LogWindow {
    fn add_log_entry(&mut self, entry: LogEntry) {
        // Check if it passes the filter
        if entry.level > self.data.filter_level {
            return;
        }
        
        if !self.data.filter_text.is_empty() && !entry.message.to_lowercase().contains(&self.data.filter_text.to_lowercase()) {
            return;
        }
        
        // Add to internal list
        self.data.log_entries.push_back(entry.clone());
        
        // Maintain max size
        while self.data.log_entries.len() > MAX_LOG_ENTRIES {
            self.data.log_entries.pop_front();
        }
        
        // Add to list view
        let index = self.log_list.len() as i32;
        let time_str = entry.timestamp.format("%H:%M:%S").to_string();
        
        let level_str = match entry.level {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        };
        
        self.log_list.insert_item(nwg::InsertListViewItem {
            index,
            column_index: 0,
            text: Some(time_str),
            image: None,
        });
        
        self.log_list.insert_item(nwg::InsertListViewItem {
            index,
            column_index: 1,
            text: Some(level_str.to_string()),
            image: None,
        });
        
        self.log_list.insert_item(nwg::InsertListViewItem {
            index,
            column_index: 2,
            text: Some(entry.target),
            image: None,
        });
        
        self.log_list.insert_item(nwg::InsertListViewItem {
            index,
            column_index: 3,
            text: Some(entry.message),
            image: None,
        });
        
        // Auto-scroll if enabled
        if self.data.auto_scroll {
            self.log_list.focus_item(index);
        }
    }
    
    fn apply_filter(&mut self) {
        // Clear the list view
        self.log_list.clear();
        
        // Re-add all entries that pass the filter
        for entry in &self.data.log_entries {
            if entry.level <= self.data.filter_level && 
               (self.data.filter_text.is_empty() || 
                entry.message.to_lowercase().contains(&self.data.filter_text.to_lowercase())) {
                
                let time_str = entry.timestamp.format("%H:%M:%S").to_string();
                let level_str = match entry.level {
                    Level::Error => "ERROR",
                    Level::Warn => "WARN",
                    Level::Info => "INFO",
                    Level::Debug => "DEBUG",
                    Level::Trace => "TRACE",
                };
                
                let index = self.log_list.len() as i32;
                
                self.log_list.insert_item(nwg::InsertListViewItem {
                    index,
                    column_index: 0,
                    text: Some(time_str),
                    image: None,
                });
                
                self.log_list.insert_item(nwg::InsertListViewItem {
                    index,
                    column_index: 1,
                    text: Some(level_str.to_string()),
                    image: None,
                });
                
                self.log_list.insert_item(nwg::InsertListViewItem {
                    index,
                    column_index: 2,
                    text: Some(entry.target.clone()),
                    image: None,
                });
                
                self.log_list.insert_item(nwg::InsertListViewItem {
                    index,
                    column_index: 3,
                    text: Some(entry.message.clone()),
                    image: None,
                });
            }
        }
    }
    
    fn clear_logs(&mut self) {
        self.data.log_entries.clear();
        self.log_list.clear();
    }
}

pub fn init_ui_logger(level: LevelFilter) -> Result<(), SetLoggerError> {
    let (tx, rx) = channel();
    
    // Set up the logger
    {
        let mut guard = LOGGER.tx.lock().unwrap();
        *guard = Some(tx);
    }
    
    // Register the logger
    log::set_logger(&LOGGER).map(|()| log::set_max_level(level))?;
    
    // Spawn a thread to handle log entries
    thread::spawn(move || {
        let mut log_entries = VecDeque::with_capacity(MAX_LOG_ENTRIES);
        
        loop {
            match rx.recv() {
                Ok(entry) => {
                    log_entries.push_back(entry);
                    while log_entries.len() > MAX_LOG_ENTRIES {
                        log_entries.pop_front();
                    }
                }
                Err(_) => break,
            }
        }
    });
    
    Ok(())
}

pub fn show_log_window() -> Result<(), std::io::Error> {
    nwg::init().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    let mut window = LogWindow::default();
    
    // Initialize UI data
    window.data = LogWindowData {
        log_entries: VecDeque::new(),
        auto_scroll: true,
        filter_level: Level::Trace,
        filter_text: String::new(),
    };
    
    nwg::Window::builder()
        .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
        .size((800, 600))
        .position((200, 200))
        .title("Security Agent Logs")
        .build(&mut window.window)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::ListView::builder()
        .parent(&window.window)
        .list_style(nwg::ListViewStyle::Detailed)
        .ex_flags(nwg::ListViewExFlags::GRID | nwg::ListViewExFlags::FULL_ROW_SELECT)
        .build(&mut window.log_list)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    // Configure columns
    window.log_list.insert_column(nwg::InsertListViewColumn {
        index: 0,
        fmt: Some(nwg::ListViewColumnFormat::LeftAlign),
        width: Some(80),
        text: Some("Time".to_string()),
    });
    
    window.log_list.insert_column(nwg::InsertListViewColumn {
        index: 1,
        fmt: Some(nwg::ListViewColumnFormat::LeftAlign),
        width: Some(60),
        text: Some("Level".to_string()),
    });
    
    window.log_list.insert_column(nwg::InsertListViewColumn {
        index: 2,
        fmt: Some(nwg::ListViewColumnFormat::LeftAlign),
        width: Some(200),
        text: Some("Module".to_string()),
    });
    
    window.log_list.insert_column(nwg::InsertListViewColumn {
        index: 3,
        fmt: Some(nwg::ListViewColumnFormat::LeftAlign),
        width: Some(460),
        text: Some("Message".to_string()),
    });
    
    nwg::ComboBox::builder()
        .parent(&window.window)
        .collection(vec!["Trace", "Debug", "Info", "Warn", "Error"])
        .selected_index(Some(0))
        .build(&mut window.level_combo)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::TextInput::builder()
        .parent(&window.window)
        .placeholder_text(Some("Filter text..."))
        .build(&mut window.filter_input)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::Button::builder()
        .parent(&window.window)
        .text("Apply Filter")
        .build(&mut window.filter_button)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::CheckBox::builder()
        .parent(&window.window)
        .text("Auto-scroll")
        .check_state(nwg::CheckBoxState::Checked)
        .build(&mut window.auto_scroll_check)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::Button::builder()
        .parent(&window.window)
        .text("Clear")
        .build(&mut window.clear_button)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::Button::builder()
        .parent(&window.window)
        .text("Close")
        .build(&mut window.close_button)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    nwg::GridLayout::builder()
        .parent(&window.window)
        .spacing(1)
        .child(0, 0, 6, 1, Some(&window.log_list))
        .child(0, 1, 1, 1, Some(&window.level_combo))
        .child(1, 1, 2, 1, Some(&window.filter_input))
        .child(3, 1, 1, 1, Some(&window.filter_button))
        .child(4, 1, 1, 1, Some(&window.auto_scroll_check))
        .child(5, 1, 1, 1, Some(&window.clear_button))
        .child(6, 1, 1, 1, Some(&window.close_button))
        .build(&mut window.layout)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    // Collect any existing log entries
    // This would need access to the logger's storage, which we simulate here
    let dummy_entries = vec![
        LogEntry {
            timestamp: Local::now(),
            level: Level::Info,
            target: "system".to_string(),
            message: "Log window initialized".to_string(),
        }
    ];
    
    for entry in dummy_entries {
        window.add_log_entry(entry);
    }
    
    // Setup event handlers
    let window_handle = window.window.handle;
    let close_handle = window.close_button.handle;
    let clear_handle = window.clear_button.handle;
    let filter_handle = window.filter_button.handle;
    let combo_handle = window.level_combo.handle;
    let check_handle = window.auto_scroll_check.handle;
    
    let window_ref = window;
    
    // Event handling closure
    let handler = move |evt: nwg::Event, _evt_data: nwg::EventData, handle: nwg::ControlHandle| {
        if evt == nwg::Event::OnButtonClick && handle == close_handle {
            nwg::stop_thread_dispatch();
        } else if evt == nwg::Event::OnButtonClick && handle == clear_handle {
            window_ref.clear_logs();
        } else if evt == nwg::Event::OnButtonClick && handle == filter_handle {
            let level_idx = window_ref.level_combo.selection().unwrap_or(0);
            window_ref.data.filter_level = match level_idx {
                0 => Level::Trace,
                1 => Level::Debug,
                2 => Level::Info,
                3 => Level::Warn,
                4 => Level::Error,
                _ => Level::Trace,
            };
            
            window_ref.data.filter_text = window_ref.filter_input.text();
            window_ref.apply_filter();
        } else if evt == nwg::Event::OnComboBoxSelection && handle == combo_handle {
            // We'll handle this in the filter button click
        } else if evt == nwg::Event::OnCheckBoxToggle && handle == check_handle {
            window_ref.data.auto_scroll = window_ref.auto_scroll_check.check_state() == nwg::CheckBoxState::Checked;
        } else if evt == nwg::Event::OnWindowClose && handle == window_handle {
            nwg::stop_thread_dispatch();
        }
    };
    
    nwg::bind_event_handler(&window_ref.window, &window_ref.window, handler);
    
    // Setup receiver for new log entries
    let (tx, rx) = channel();
    
    // This would normally be connected to the actual logger
    thread::spawn(move || {
        // This is just a placeholder to simulate getting log entries
        // In a real implementation, this would be connected to the logger's output
    });
    
    nwg::dispatch_thread_events();
    
    Ok(())
}