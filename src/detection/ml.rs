use log::{info, warn, error, debug};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use onnxruntime::{environment::Environment, session::Session, tensor::OrtTensor};
use ndarray::{Array, ArrayD, Dim};
use std::convert::TryFrom;
use std::fs;
use crate::ui::alerts;
use crate::monitors;

#[derive(Error, Debug)]
pub enum MLDetectionError {
    #[error("ML Engine not initialized")]
    NotInitialized,
    #[error("Model not found: {0}")]
    ModelNotFound(String),
    #[error("Invalid model configuration: {0}")]
    InvalidModelConfig(String),
    #[error("Prediction error: {0}")]
    PredictionError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("ONNX runtime error: {0}")]
    OnnxError(#[from] onnxruntime::error::OrtError),
    #[error("Feature extraction error: {0}")]
    FeatureExtractionError(String),
}

#[derive(Debug, Clone)]
pub enum ModelType {
    ProcessClassifier,
    NetworkClassifier,
    FileClassifier,
    BehaviorClassifier,
}

#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub model_type: ModelType,
    pub model_path: PathBuf,
    pub input_name: String,
    pub output_name: String,
    pub threshold: f32,
    pub feature_count: usize,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Prediction {
    pub model_type: ModelType,
    pub label: String,
    pub confidence: f32,
    pub source: String,
    pub details: HashMap<String, String>,
    pub is_malicious: bool,
}

struct MLEngineState {
    environment: Environment,
    models: HashMap<ModelType, (Session, ModelConfig)>,
    initialized: bool,
}

pub struct MLEngine {
    state: Arc<Mutex<MLEngineState>>,
}

impl MLEngine {
    pub fn new() -> Result<Self, MLDetectionError> {
        let environment = Environment::builder()
            .with_name("security_agent_ml")
            .build()
            .map_err(MLDetectionError::OnnxError)?;
        
        Ok(MLEngine {
            state: Arc::new(Mutex::new(MLEngineState {
                environment,
                models: HashMap::new(),
                initialized: false,
            })),
        })
    }
    
    pub fn initialize(&self, models_dir: &Path) -> Result<(), MLDetectionError> {
        let mut state = self.state.lock().unwrap();
        
        // Ensure models directory exists
        if !models_dir.exists() {
            fs::create_dir_all(models_dir)?;
        }
        
        // Load default models if available
        self.load_default_models(&mut state, models_dir)?;
        
        state.initialized = true;
        info!("ML Engine initialized with {} models", state.models.len());
        
        Ok(())
    }
    
    fn load_default_models(&self, state: &mut MLEngineState, models_dir: &Path) -> Result<(), MLDetectionError> {
        // Check for process classifier model
        let process_model_path = models_dir.join("process_classifier.onnx");
        if process_model_path.exists() {
            let config = ModelConfig {
                model_type: ModelType::ProcessClassifier,
                model_path: process_model_path.clone(),
                input_name: "input".to_string(),
                output_name: "output".to_string(),
                threshold: 0.7,
                feature_count: 50,
                labels: vec!["benign".to_string(), "malicious".to_string()],
            };
            
            self.load_model(state, config)?;
        }
        
        // Check for network classifier model
        let network_model_path = models_dir.join("network_classifier.onnx");
        if network_model_path.exists() {
            let config = ModelConfig {
                model_type: ModelType::NetworkClassifier,
                model_path: network_model_path.clone(),
                input_name: "input".to_string(),
                output_name: "output".to_string(),
                threshold: 0.8,
                feature_count: 30,
                labels: vec!["benign".to_string(), "malicious".to_string()],
            };
            
            self.load_model(state, config)?;
        }
        
        // Check for file classifier model
        let file_model_path = models_dir.join("file_classifier.onnx");
        if file_model_path.exists() {
            let config = ModelConfig {
                model_type: ModelType::FileClassifier,
                model_path: file_model_path.clone(),
                input_name: "input".to_string(),
                output_name: "output".to_string(),
                threshold: 0.75,
                feature_count: 100,
                labels: vec!["benign".to_string(), "ransomware".to_string(), "trojan".to_string(), "worm".to_string()],
            };
            
            self.load_model(state, config)?;
        }
        
        Ok(())
    }
    
    pub fn load_model(&self, state: &mut MLEngineState, config: ModelConfig) -> Result<(), MLDetectionError> {
        if !config.model_path.exists() {
            return Err(MLDetectionError::ModelNotFound(config.model_path.to_string_lossy().to_string()));
        }
        
        let session = state.environment
            .new_session_builder()?
            .with_model_from_file(&config.model_path)?;
        
        state.models.insert(config.model_type.clone(), (session, config));
        debug!("Loaded ML model: {:?}", config.model_path);
        
        Ok(())
    }
    
    pub fn predict_process(&self, process_name: &str, features: Vec<f32>) -> Result<Prediction, MLDetectionError> {
        let state = self.state.lock().unwrap();
        
        if !state.initialized {
            return Err(MLDetectionError::NotInitialized);
        }
        
        if let Some((session, config)) = state.models.get(&ModelType::ProcessClassifier) {
            self.run_prediction(session, config, features, process_name)
        } else {
            Err(MLDetectionError::ModelNotFound("Process classifier model not loaded".to_string()))
        }
    }
    
    pub fn predict_network(&self, connection_info: &str, features: Vec<f32>) -> Result<Prediction, MLDetectionError> {
        let state = self.state.lock().unwrap();
        
        if !state.initialized {
            return Err(MLDetectionError::NotInitialized);
        }
        
        if let Some((session, config)) = state.models.get(&ModelType::NetworkClassifier) {
            self.run_prediction(session, config, features, connection_info)
        } else {
            Err(MLDetectionError::ModelNotFound("Network classifier model not loaded".to_string()))
        }
    }
    
    pub fn predict_file(&self, file_path: &str, features: Vec<f32>) -> Result<Prediction, MLDetectionError> {
        let state = self.state.lock().unwrap();
        
        if !state.initialized {
            return Err(MLDetectionError::NotInitialized);
        }
        
        if let Some((session, config)) = state.models.get(&ModelType::FileClassifier) {
            self.run_prediction(session, config, features, file_path)
        } else {
            Err(MLDetectionError::ModelNotFound("File classifier model not loaded".to_string()))
        }
    }
    
    fn run_prediction(&self, session: &Session, config: &ModelConfig, features: Vec<f32>, source: &str) 
        -> Result<Prediction, MLDetectionError> 
    {
        // Validate feature vector length
        if features.len() != config.feature_count {
            return Err(MLDetectionError::FeatureExtractionError(
                format!("Expected {} features, got {}", config.feature_count, features.len())
            ));
        }
        
        // Prepare input tensor
        let shape = vec![1, features.len() as i64];
        let array = Array::from_shape_vec(Dim(shape), features.clone())
            .map_err(|e| MLDetectionError::PredictionError(e.to_string()))?;
        
        let input_tensor = OrtTensor::try_from(array)
            .map_err(|e| MLDetectionError::PredictionError(e.to_string()))?;
        
        // Run prediction
        let inputs = HashMap::from([(config.input_name.clone(), input_tensor)]);
        let outputs = session.run(inputs)?;
        
        // Extract prediction results
        if let Some(output) = outputs.get(&config.output_name) {
            let output_array: ArrayD<f32> = output.try_extract()
                .map_err(|e| MLDetectionError::PredictionError(e.to_string()))?;
            
            // Get highest probability class
            let flat_view = output_array.view().into_shape(config.labels.len())
                .map_err(|e| MLDetectionError::PredictionError(e.to_string()))?;
            
            let mut max_prob = 0.0;
            let mut max_idx = 0;
            
            for (i, &prob) in flat_view.iter().enumerate() {
                if prob > max_prob {
                    max_prob = prob;
                    max_idx = i;
                }
            }
            
            // Create prediction result
            let label = config.labels.get(max_idx)
                .ok_or_else(|| MLDetectionError::PredictionError("Invalid label index".to_string()))?
                .clone();
            
            let is_malicious = max_idx > 0 && max_prob >= config.threshold;
            
            let mut details = HashMap::new();
            for (i, label_name) in config.labels.iter().enumerate() {
                if let Some(&prob) = flat_view.get(i) {
                    details.insert(label_name.clone(), format!("{:.2}%", prob * 100.0));
                }
            }
            
            let prediction = Prediction {
                model_type: config.model_type.clone(),
                label,
                confidence: max_prob,
                source: source.to_string(),
                details,
                is_malicious,
            };
            
            // If malicious with high confidence, generate an alert
            if is_malicious {
                let alert_type = if max_prob > 0.9 {
                    alerts::AlertType::Critical
                } else if max_prob > 0.8 {
                    alerts::AlertType::Threat
                } else {
                    alerts::AlertType::Warning
                };
                
                let alert_title = match config.model_type {
                    ModelType::ProcessClassifier => format!("Suspicious Process Detected: {}", source),
                    ModelType::NetworkClassifier => format!("Suspicious Network Activity: {}", source),
                    ModelType::FileClassifier => format!("Suspicious File Detected: {}", source),
                    ModelType::BehaviorClassifier => format!("Suspicious Behavior: {}", source),
                };
                
                let alert_message = format!(
                    "ML detection classified as '{}' with {:.1}% confidence",
                    prediction.label,
                    prediction.confidence * 100.0
                );
                
                alerts::add_alert(alert_type, &alert_title, &alert_message);
            }
            
            Ok(prediction)
        } else {
            Err(MLDetectionError::PredictionError(format!("Output '{}' not found", config.output_name)))
        }
    }
}

// Singleton pattern for global access
lazy_static::lazy_static! {
    static ref ML_ENGINE: Arc<Mutex<Option<MLEngine>>> = Arc::new(Mutex::new(None));
}

pub fn initialize(models_dir: &Path) -> Result<(), MLDetectionError> {
    let engine = MLEngine::new()?;
    engine.initialize(models_dir)?;
    
    let mut ml_engine = ML_ENGINE.lock().unwrap();
    *ml_engine = Some(engine);
    
    Ok(())
}

pub fn predict_process(process_name: &str, features: Vec<f32>) -> Result<Prediction, MLDetectionError> {
    let ml_engine = ML_ENGINE.lock().unwrap();
    
    if let Some(engine) = &*ml_engine {
        engine.predict_process(process_name, features)
    } else {
        Err(MLDetectionError::NotInitialized)
    }
}

pub fn predict_network(connection_info: &str, features: Vec<f32>) -> Result<Prediction, MLDetectionError> {
    let ml_engine = ML_ENGINE.lock().unwrap();
    
    if let Some(engine) = &*ml_engine {
        engine.predict_network(connection_info, features)
    } else {
        Err(MLDetectionError::NotInitialized)
    }
}

pub fn predict_file(file_path: &str, features: Vec<f32>) -> Result<Prediction, MLDetectionError> {
    let ml_engine = ML_ENGINE.lock().unwrap();
    
    if let Some(engine) = &*ml_engine {
        engine.predict_file(file_path, features)
    } else {
        Err(MLDetectionError::NotInitialized)
    }
}

// Feature extraction utilities
pub fn extract_process_features(process_name: &str) -> Result<Vec<f32>, MLDetectionError> {
    // This is a placeholder for actual feature extraction
    // In a real implementation, this would extract meaningful features from the process
    
    // For demonstration purposes, we just create a dummy feature vector
    let mut features = vec![0.0; 50];
    
    // Example features (in a real system these would be meaningful metrics)
    features[0] = 1.0; // Process is running
    
    // Just a simple heuristic for demo - if process name contains "suspicious", mark it as such
    if process_name.to_lowercase().contains("suspicious") {
        features[1] = 1.0;
    }
    
    Ok(features)
}

pub fn extract_network_features(connection_info: &str) -> Result<Vec<f32>, MLDetectionError> {
    // Placeholder for actual feature extraction
    let mut features = vec![0.0; 30];
    
    // Example features
    features[0] = 1.0; // Active connection
    
    // Simple heuristic for demo
    if connection_info.contains(":4444") || connection_info.contains(":1337") {
        features[1] = 1.0; // Common backdoor ports
    }
    
    Ok(features)
}

pub fn extract_file_features(file_path: &str) -> Result<Vec<f32>, MLDetectionError> {
    // Placeholder for actual feature extraction
    let mut features = vec![0.0; 100];
    
    // Example features
    features[0] = 1.0; // File exists
    
    // Simple heuristic for demo
    if file_path.ends_with(".exe") || file_path.ends_with(".dll") {
        features[1] = 1.0; // Executable file
    }
    
    Ok(features)
}