//! Optional web administration service for RustVPN.
//!
//! This crate deliberately stays outside the packet path.  The server
//! implements [`AdminBackend`] and [`SessionObserver`], and the admin service
//! only reads snapshots, samples counters and requests explicit actions.

pub mod api;
pub mod auth;
pub mod config_edit;
pub mod history;
pub mod model;
pub mod state;
pub mod store;

pub use model::*;
pub use state::{AdminOptions, AdminState};

use std::sync::Arc;

/// Serve the admin UI/API on an already-bound listener.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<AdminState>,
) -> anyhow::Result<()> {
    state.spawn_sampler();
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}
