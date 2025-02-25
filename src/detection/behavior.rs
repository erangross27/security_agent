use log::{info, warn, error, debug};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use crate::ui::alerts;

#[derive(Error, Debug)]
pub enum BehaviorDetectionError {
    #[error("Analyzer not initialized")]
    NotInitialized,
    #[error("Invalid behavior pattern: {0}")]
    InvalidPattern(String),
    #[error("Error processing event: {0}")]
    EventProcessingError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventType {
    ProcessStart,
    ProcessTermination,
    FileCreated,
    FileModified,
    FileDeleted,
    NetworkConnection,
    NetworkListen,
    DnsRequest,
    RegistryModified,
    SystemConfigChanged,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: EventType,
    pub timestamp: Instant,
    pub source: String,      // Process name, file path, etc.
    pub target: Option<String>, // Target of the action if applicable
    pub details: HashMap<String, String>, // Additional context
}

impl Event {
    pub fn new(
        event_type: EventType,
        source: &str,
        target: Option<&str>,
        details: HashMap<String, String>
    ) -> Self {
        Event {
            event_type,
            timestamp: Instant::now(),
            source: source.to_string(),
            target: target.map(|s| s.to_string()),
            details,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub name: String,
    pub description: String,
    pub severity: u8, // 1-10 scale
    pub events: Vec<EventType>,
    pub timeframe: Duration,
    pub min_occurrence: usize,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub pattern: Pattern,
    pub matched_events: Vec<Event>,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

struct BehaviorState {
    patterns: Vec<Pattern>,
    event_history: VecDeque<Event>,
    active_alerts: Vec<Alert>,
    max_event_history: usize,
    initialized: bool,
}

pub struct BehaviorAnalyzer {
    state: Arc<Mutex<BehaviorState>>,
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        BehaviorAnalyzer {
            state: Arc::new(Mutex::new(BehaviorState {
                patterns: Vec::new(),
                event_history: VecDeque::new(),
                active_alerts: Vec::new(),
                max_event_history: 10000,
                initialized: false,
            })),
        }
    }
    
    pub fn initialize(&self) -> Result<(), BehaviorDetectionError> {
        let mut state = self.state.lock().unwrap();
        
        // Add default patterns
        self.add_default_patterns(&mut state);
        
        state.initialized = true;
        info!("Behavior analyzer initialized with {} patterns", state.patterns.len());
        
        Ok(())
    }
    
    fn add_default_patterns(&self, state: &mut BehaviorState) {
        // Pattern 1: Ransomware-like behavior (multiple file modifications in short time)
        state.patterns.push(Pattern {
            name: "Potential Ransomware Activity".to_string(),
            description: "Multiple files modified or deleted in rapid succession".to_string(),
            severity: 9,
            events: vec![EventType::FileModified, EventType::FileDeleted],
            timeframe: Duration::from_secs(60),
            min_occurrence: 20,
        });
        
        // Pattern 2: Network scanning behavior
        state.patterns.push(Pattern {
            name: "Network Scanning Detected".to_string(),
            description: "Multiple outbound connection attempts in short succession".to_string(),
            severity: 7,
            events: vec![EventType::NetworkConnection],
            timeframe: Duration::from_secs(30),
            min_occurrence: 15,
        });
        
        // Pattern 3: Suspicious registry modifications
        state.patterns.push(Pattern {
            name: "System Configuration Change".to_string(),
            description: "Multiple registry keys modified related to startup or security".to_string(),
            severity: 8,
            events: vec![EventType::RegistryModified],
            timeframe: Duration::from_secs(120),
            min_occurrence: 5,
        });
        
        // Pattern 4: Process injection indicators
        state.patterns.push(Pattern {
            name: "Potential Process Injection".to_string(),
            description: "Process creation followed by suspicious memory operations".to_string(),
            severity: 8,
            events: vec![EventType::ProcessStart, EventType::SystemConfigChanged],
            timeframe: Duration::from_secs(10),
            min_occurrence: 2,
        });
    }
    
    pub fn add_pattern(&self, pattern: Pattern) -> Result<(), BehaviorDetectionError> {
        let mut state = self.state.lock().unwrap();
        
        if pattern.events.is_empty() {
            return Err(BehaviorDetectionError::InvalidPattern("Pattern must contain at least one event".to_string()));
        }
        
        if pattern.min_occurrence == 0 {
            return Err(BehaviorDetectionError::InvalidPattern("Minimum occurrence must be greater than zero".to_string()));
        }
        
        state.patterns.push(pattern.clone());
        debug!("Added new behavior pattern: {}", pattern.name);
        
        Ok(())
    }
    
    pub fn process_event(&self, event: Event) -> Result<Vec<Alert>, BehaviorDetectionError> {
        let mut state = self.state.lock().unwrap();
        
        if !state.initialized {
            return Err(BehaviorDetectionError::NotInitialized);
        }
        
        // Add event to history
        state.event_history.push_back(event.clone());
        
        // Keep event history under max size
        while state.event_history.len() > state.max_event_history {
            state.event_history.pop_front();
        }
        
        // Check patterns against event history
        let mut new_alerts = Vec::new();
        
        for pattern in &state.patterns {
            if pattern.events.contains(&event.event_type) {
                // This pattern might match, analyze recent events
                let matched_events = self.check_pattern_match(&state, pattern);
                
                if matched_events.len() >= pattern.min_occurrence {
                    // Pattern matched
                    let first_event_time = matched_events.iter()
                        .map(|e| e.timestamp)
                        .min()
                        .unwrap_or(Instant::now());
                    
                    let alert = Alert {
                        pattern: pattern.clone(),
                        matched_events: matched_events.clone(),
                        first_seen: first_event_time,
                        last_seen: Instant::now(),
                    };
                    
                    // Add to active alerts if not already there
                    if !state.active_alerts.iter().any(|a| a.pattern.name == pattern.name) {
                        state.active_alerts.push(alert.clone());
                        new_alerts.push(alert);
                    }
                }
            }
        }
        
        // For any new alerts, send to UI alert system
        for alert in &new_alerts {
            let alert_type = match alert.pattern.severity {
                1..=3 => alerts::AlertType::Info,
                4..=6 => alerts::AlertType::Warning,
                7..=8 => alerts::AlertType::Threat,
                _ => alerts::AlertType::Critical,
            };
            
            alerts::add_alert(
                alert_type,
                &alert.pattern.name,
                &format!("{}: {} events detected", alert.pattern.description, alert.matched_events.len())
            );
        }
        
        Ok(new_alerts)
    }
    
    fn check_pattern_match(&self, state: &BehaviorState, pattern: &Pattern) -> Vec<Event> {
        let now = Instant::now();
        let time_threshold = now - pattern.timeframe;
        
        // Filter events that:
        // 1. Match the pattern's event types
        // 2. Are within the timeframe
        state.event_history.iter()
            .filter(|e| pattern.events.contains(&e.event_type))
            .filter(|e| e.timestamp >= time_threshold)
            .cloned()
            .collect()
    }
    
    pub fn get_active_alerts(&self) -> Vec<Alert> {
        let state = self.state.lock().unwrap();
        state.active_alerts.clone()
    }
    
    pub fn clear_alerts(&self) {
        let mut state = self.state.lock().unwrap();
        state.active_alerts.clear();
    }
}

// Singleton pattern for global access
lazy_static::lazy_static! {
    static ref ANALYZER: BehaviorAnalyzer = BehaviorAnalyzer::new();
}

pub fn initialize() -> Result<(), BehaviorDetectionError> {
    ANALYZER.initialize()
}

pub fn process_event(event: Event) -> Result<Vec<Alert>, BehaviorDetectionError> {
    ANALYZER.process_event(event)
}

pub fn add_pattern(pattern: Pattern) -> Result<(), BehaviorDetectionError> {
    ANALYZER.add_pattern(pattern)
}

pub fn get_active_alerts() -> Vec<Alert> {
    ANALYZER.get_active_alerts()
}

pub fn clear_alerts() {
    ANALYZER.clear_alerts()
}