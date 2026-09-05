//! Content-addressed identities and verified restoration for WhatsApp Web inputs.
//!
//! This crate owns the durable boundary between remote JS/wasm artifacts and tools
//! that consume them. Protocol extraction and codec-specific derivation stay in their
//! respective consumers.

pub mod lock;

#[cfg(feature = "restore")]
pub mod capture;

#[cfg(feature = "restore")]
pub mod restore;
