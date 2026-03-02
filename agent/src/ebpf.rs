use crate::error::{AgentError, Result};
use crate::events::Event;
use crate::network::BackendClient;
use aya::{
    maps::ring_buf::{RingBuf, RingBufItem},
    programs::TracePoint,
    Bpf, BpfLoader,
};
use aya::include_bytes_aligned;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct EbpfAgent {
    bpf: Bpf,
    backend: Arc<BackendClient>,
    tx: mpsc::Sender<Event>,
}

impl EbpfAgent {
    pub async fn new(backend_url: String, tx: mpsc::Sender<Event>) -> Result<Self> {
        info!("Loading eBPF program...");
        
        let bpf_bytes = include_bytes_aligned!("../../target/bpf/secure_agent.bpf.o");
        
        let bpf = BpfLoader::new()
            .load(bpf_bytes)
            .map_err(|e| {
                error!("Failed to load BPF program: {}", e);
                AgentError::BpfLoadError(e)
            })?;

        info!("eBPF program loaded successfully");

        let backend = Arc::new(BackendClient::new(backend_url));

        Ok(Self { bpf, backend, tx })
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Attaching eBPF programs...");

        self.attach_tracepoint("trace_openat", "syscalls", "sys_enter_openat")?;
        self.attach_tracepoint("trace_connect", "syscalls", "sys_enter_connect")?;

        info!("All eBPF programs attached successfully");

        let mut ring_buf = RingBuf::try_from(self.bpf.map_mut("events_ringbuf")?)
            .map_err(|e| {
                error!("Failed to initialize ring buffer: {}", e);
                AgentError::from(e)
            })?;

        info!("Ring buffer initialized, starting event loop...");

        self.event_loop(&mut ring_buf).await
    }

    fn attach_tracepoint(&mut self, prog_name: &str, category: &str, name: &str) -> Result<()> {
        let prog: &mut TracePoint = self
            .bpf
            .program_mut(prog_name)
            .ok_or_else(|| {
                let err = AgentError::ProgramNotFound {
                    name: prog_name.to_string(),
                };
                error!("{}", err);
                err
            })?
            .try_into()
            .map_err(|e| {
                error!("Failed to convert program '{}': {}", prog_name, e);
                AgentError::BpfLoadError(e)
            })?;

        prog.load().map_err(|e| AgentError::BpfAttachError {
            program: prog_name.to_string(),
            source: e,
        })?;

        prog.attach(category, name).map_err(|e| AgentError::BpfAttachError {
            program: prog_name.to_string(),
            source: e,
        })?;

        info!("Attached '{}' to {}/{}", prog_name, category, name);
        Ok(())
    }

    async fn event_loop(&mut self, ring_buf: &mut RingBuf) -> Result<()> {
        loop {
            while let Some(item) = ring_buf.next() {
                match self.handle_event(item) {
                    Ok(_) => debug!("Event handled successfully"),
                    Err(e) => error!("Error handling event: {}", e),
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    fn handle_event(&self, item: RingBufItem) -> Result<()> {
        let data = item.as_ptr();
        
        if data.is_null() {
            return Err(AgentError::InvalidEventData("Null pointer received".to_string()));
        }

        let event = unsafe { std::ptr::read(data as *const Event) };

        if !event.is_valid() {
            debug!("Skipping invalid event: PID={}", event.pid);
            return Ok(());
        }

        debug!(
            "Event received: PID={}, Type={}, UID={}",
            event.pid,
            event.get_event_type(),
            event.uid
        );

        let backend = Arc::clone(&self.backend);
        let tx = self.tx.clone();

        tokio::spawn(async move {
            if let Err(e) = backend.send_event(&event).await {
                error!("Failed to send event to backend: {}", e);
            }

            if let Err(e) = tx.send(event).await {
                error!("Failed to send event to local channel: {}", e);
            }
        });

        Ok(())
    }
}