use crate::error::{AgentError, Result};
use crate::events::Event;
use log::{debug, error, info, warn};
use reqwest::{Client, Response};
use std::time::Duration;

pub struct BackendClient {
    client: Client,
    base_url: String,
    retry_count: u32,
}

impl BackendClient {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            base_url,
            retry_count: 3,
        }
    }

    pub fn with_retry(mut self, retry_count: u32) -> Self {
        self.retry_count = retry_count;
        self
    }

    pub async fn send_event(&self, event: &Event) -> Result<()> {
        let url = format!("{}/api/events", self.base_url);
        
        for attempt in 1..=self.retry_count {
            match self.try_send_event(&url, event).await {
                Ok(_) => {
                    info!("Event sent successfully (attempt {})", attempt);
                    return Ok(());
                }
                Err(e) => {
                    if attempt == self.retry_count {
                        error!("Failed to send event after {} attempts: {}", attempt, e);
                        return Err(e);
                    }
                    warn!(
                        "Attempt {} failed, retrying in {}ms: {}",
                        attempt,
                        attempt * 100,
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(attempt as u64 * 100)).await;
                }
            }
        }

        Err(AgentError::BackendError("Max retries exceeded".to_string()))
    }

    async fn try_send_event(&self, url: &str, event: &Event) -> Result<()> {
        let response = self.client.post(url).json(event).send().await?;
        
        self.handle_response(response).await
    }

    async fn handle_response(&self, response: Response) -> Result<()> {
        let status = response.status();
        
        if status.is_success() {
            debug!("Backend responded with status: {}", status);
            Ok(())
        } else if status.is_client_error() {
            let body = response.text().await.unwrap_or_default();
            error!("Client error from backend: {} - {}", status, body);
            Err(AgentError::BackendError(format!(
                "Client error: {} - {}",
                status, body
            )))
        } else if status.is_server_error() {
            let body = response.text().await.unwrap_or_default();
            error!("Server error from backend: {} - {}", status, body);
            Err(AgentError::BackendError(format!(
                "Server error: {} - {}",
                status, body
            )))
        } else {
            Err(AgentError::BackendError(format!(
                "Unexpected status: {}",
                status
            )))
        }
    }

    pub async fn health_check(&self) -> bool {
        let url = format!("{}/health", self.base_url);
        
        match self.client.get(&url).send().await {
            Ok(response) => response.status().is_success(),
            Err(e) => {
                warn!("Health check failed: {}", e);
                false
            }
        }
    }
}

impl Clone for BackendClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            retry_count: self.retry_count,
        }
    }
}