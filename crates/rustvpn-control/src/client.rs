//! Client side of the control protocol.

use std::path::Path;

use tokio::net::UnixStream;

use crate::frame::{read_frame, write_frame, FrameError};
use crate::proto::{
    Event, KickReport, ReloadReport, Request, Response, ServerStatus, SessionEnded, SessionInfo,
};
use crate::PROTOCOL_VERSION;

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("control socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("control framing: {0}")]
    Frame(#[from] FrameError),
    #[error("control server: {0}")]
    Remote(String),
    #[error("unexpected control response")]
    Unexpected,
}

pub type Result<T> = std::result::Result<T, ControlError>;

pub struct ControlClient {
    stream: UnixStream,
    pub server_version: String,
    pub server_instance: u64,
}

impl ControlClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let mut stream = UnixStream::connect(path.as_ref()).await?;
        write_frame(
            &mut stream,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await?;
        let response: Response = read_frame(&mut stream)
            .await?
            .ok_or(ControlError::Unexpected)?;
        match response {
            Response::Hello {
                version,
                server_version,
                server_instance,
            } if version == PROTOCOL_VERSION => Ok(Self {
                stream,
                server_version,
                server_instance,
            }),
            Response::Hello { version, .. } => Err(ControlError::Remote(format!(
                "control protocol mismatch: server speaks v{version}, client speaks v{PROTOCOL_VERSION}"
            ))),
            Response::Error { message } => Err(ControlError::Remote(message)),
            _ => Err(ControlError::Unexpected),
        }
    }

    pub async fn request(&mut self, request: &Request) -> Result<Response> {
        write_frame(&mut self.stream, request).await?;
        let response: Response = read_frame(&mut self.stream)
            .await?
            .ok_or(ControlError::Unexpected)?;
        response.into_result().map_err(ControlError::Remote)
    }

    pub async fn status(&mut self) -> Result<ServerStatus> {
        match self.request(&Request::Status).await? {
            Response::Status { status } => Ok(status),
            _ => Err(ControlError::Unexpected),
        }
    }

    pub async fn sessions(&mut self) -> Result<Vec<SessionInfo>> {
        match self.request(&Request::Sessions).await? {
            Response::Sessions { sessions } => Ok(sessions),
            _ => Err(ControlError::Unexpected),
        }
    }

    pub async fn kick(&mut self, id: &str, reason: &str) -> Result<KickReport> {
        match self
            .request(&Request::Kick {
                id: id.to_string(),
                reason: reason.to_string(),
            })
            .await?
        {
            Response::Kick { report } => Ok(report),
            _ => Err(ControlError::Unexpected),
        }
    }

    pub async fn reload(&mut self) -> Result<ReloadReport> {
        match self.request(&Request::Reload).await? {
            Response::Reload { report } => Ok(report),
            _ => Err(ControlError::Unexpected),
        }
    }

    pub async fn recent_sessions(&mut self, limit: u32) -> Result<Vec<SessionEnded>> {
        match self.request(&Request::RecentSessions { limit }).await? {
            Response::RecentSessions { sessions } => Ok(sessions),
            _ => Err(ControlError::Unexpected),
        }
    }

    pub async fn subscribe(mut self) -> Result<Subscription> {
        match self.request(&Request::Subscribe).await? {
            Response::Subscribed => Ok(Subscription {
                stream: self.stream,
            }),
            _ => Err(ControlError::Unexpected),
        }
    }
}

pub struct Subscription {
    stream: UnixStream,
}

impl Subscription {
    pub async fn next(&mut self) -> Result<Option<Event>> {
        Ok(read_frame(&mut self.stream).await?)
    }
}

/// Connect, perform the version handshake and issue one request.
pub async fn call_once(path: impl AsRef<Path>, request: &Request) -> Result<Response> {
    let mut client = ControlClient::connect(path).await?;
    client.request(request).await
}

/// Connect and subscribe in one step.
pub async fn subscribe(path: impl AsRef<Path>) -> Result<Subscription> {
    ControlClient::connect(path).await?.subscribe().await
}
