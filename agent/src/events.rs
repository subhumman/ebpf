use serde::{Deserialize, Serialize};
use std::fmt;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    FileOpen = 1, 
    NetworkConnect = 2,
    Unknown = 0,
}

impl From<u32> for EventType{
    fn from(value: u32) -> Self{
        match value {
            1 => EventType::FileOpen,
            2 => EventType::NetworkConnect,
            _ => EventType::Unknown,
        }
    }
}

impl fmt::Display for EventType{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        match self{
            EventType::FileOpen => write!(f, "FileOpen"),
            EventType::NetworkConnect => write!(f, "NetworkConncet"),
            EventType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Event{
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub event_type: u32,
    pub filename: [u8; 256],
    pub dest_ip: u32,
    pub dest_port: u16,
    _padding: u16
}

impl Event {
    pub fn get_filename(&self) -> Result<String, std::str::Utf8Error> {
        let len = self.filename.iter().position(|&c| c == 0).unwrap_or(256);
        std::str::from_utf8(&self.filename[..len]).map(|s| s.to_string())
    }

    pub fn get_filename_lossy(&self) -> String {
        String::from_utf8_lossy(&self.filename[..self
            .filename
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(256)])
        .to_string()
    }

    pub fn get_dest_ip(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.dest_ip & 0xFF,
            (self.dest_ip >> 8) & 0xFF,
            (self.dest_ip >> 16) & 0xFF,
            (self.dest_ip >> 24) & 0xFF
        )
    }

    pub fn get_event_type(&self) -> EventType {
        self.event_type.into()
    }

    pub fn is_valid(&self) -> bool {
        self.pid > 0 && self.event_type > 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDto {
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub event_type: String,
    pub filename: Option<String>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,
}

impl From<&Event> for EventDto {
    fn from(event: &Event) -> Self {
        let (filename, dest_ip, dest_port) = match event.get_event_type() {
            EventType::FileOpen => (Some(event.get_filename_lossy()), None, None),
            EventType::NetworkConnect => (None, Some(event.get_dest_ip()), Some(event.dest_port)),
            EventType::Unknown => (None, None, None),
        };

        Self {
            pid: event.pid,
            uid: event.uid,
            timestamp: event.timestamp,
            event_type: event.get_event_type().to_string(),
            filename,
            dest_ip,
            dest_port,
        }
    }
}