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