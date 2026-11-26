//! Small synchronous-looking client used by the GUI and tests.

use std::path::Path;

use crate::frame::{read_frame, write_frame, FrameError};
use crate::proto::{Request, Response};
use crate::transport::{self, AsyncStream, DefaultStream};
use crate::PROTOCOL_VERSION;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connect client daemon: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("client daemon: {0}")]
    Remote(String),
    #[error("client daemon protocol error: {0}")]
    Protocol(String),
}

/// IPC client.  The default transport is a Unix socket on Unix and a named
/// pipe on Windows; [`Client::connect_stream`] accepts any stream that
/// implements [`AsyncStream`] (used by tests and future transports).
pub struct Client<S = DefaultStream> {
    stream: S,
}

impl Client<DefaultStream> {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let stream = transport::connect(path.as_ref()).await?;
        Self::connect_stream(stream).await
    }
}

impl<S: AsyncStream> Client<S> {
    /// Perform the Hello handshake on an already connected stream.
    pub async fn connect_stream(mut stream: S) -> Result<Self, ClientError> {
        write_frame(
            &mut stream,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await?;
        let response: Response = read_frame(&mut stream)
            .await?
            .ok_or_else(|| ClientError::Protocol("daemon closed during hello".into()))?;
        match response.into_result() {
            Ok(Response::Hello { version, .. }) if version == PROTOCOL_VERSION => {
                Ok(Self { stream })
            }
            Ok(Response::Hello { version, .. }) => Err(ClientError::Protocol(format!(
                "daemon speaks v{version}, client speaks v{PROTOCOL_VERSION}"
            ))),
            Ok(other) => Err(ClientError::Protocol(format!(
                "unexpected hello response: {other:?}"
            ))),
            Err(message) => Err(ClientError::Remote(message)),
        }
    }

    pub async fn request(&mut self, request: Request) -> Result<Response, ClientError> {
        write_frame(&mut self.stream, &request).await?;
        let response: Response = read_frame(&mut self.stream)
            .await?
            .ok_or_else(|| ClientError::Protocol("daemon closed the connection".into()))?;
        response.into_result().map_err(ClientError::Remote)
    }

    pub async fn status(&mut self) -> Result<crate::proto::EngineStatus, ClientError> {
        match self.request(Request::Status).await? {
            Response::Status { status } => Ok(*status),
            other => Err(ClientError::Protocol(format!(
                "unexpected status response: {other:?}"
            ))),
        }
    }

    pub async fn connect_profile(
        &mut self,
        profile: crate::proto::ProfileSpec,
        password: String,
    ) -> Result<(), ClientError> {
        match self
            .request(Request::Connect {
                profile: Box::new(profile),
                password,
            })
            .await?
        {
            Response::Ok => Ok(()),
            other => Err(ClientError::Protocol(format!(
                "unexpected connect response: {other:?}"
            ))),
        }
    }

    pub async fn disconnect(&mut self) -> Result<(), ClientError> {
        match self.request(Request::Disconnect).await? {
            Response::Ok => Ok(()),
            other => Err(ClientError::Protocol(format!(
                "unexpected disconnect response: {other:?}"
            ))),
        }
    }

    pub async fn logs(&mut self, limit: u32) -> Result<Vec<crate::proto::LogLine>, ClientError> {
        match self.request(Request::Logs { limit }).await? {
            Response::Logs { lines } => Ok(lines),
            other => Err(ClientError::Protocol(format!(
                "unexpected logs response: {other:?}"
            ))),
        }
    }
}

#[cfg(windows)]
impl Client<DefaultStream> {
    /// PID of the daemon that accepted this pipe.  M4 uses this to verify the
    /// server image before the GUI sends a password.
    pub fn server_pid(&self) -> std::io::Result<u32> {
        transport::pipe_server_pid(&self.stream)
    }
}

pub struct EventStream<S = DefaultStream> {
    stream: S,
}

impl EventStream<DefaultStream> {
    pub async fn subscribe(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let stream = transport::connect(path.as_ref()).await?;
        Self::subscribe_stream(stream).await
    }
}

impl<S: AsyncStream> EventStream<S> {
    /// Perform Hello + Subscribe on an already connected stream.
    pub async fn subscribe_stream(mut stream: S) -> Result<Self, ClientError> {
        write_frame(
            &mut stream,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await?;
        let hello: Response = read_frame(&mut stream)
            .await?
            .ok_or_else(|| ClientError::Protocol("daemon closed during hello".into()))?;
        match hello.into_result() {
            Ok(Response::Hello { version, .. }) if version == PROTOCOL_VERSION => {}
            Ok(Response::Hello { version, .. }) => {
                return Err(ClientError::Protocol(format!(
                    "daemon speaks v{version}, client speaks v{PROTOCOL_VERSION}"
                )))
            }
            Ok(other) => {
                return Err(ClientError::Protocol(format!(
                    "unexpected hello response: {other:?}"
                )))
            }
            Err(message) => return Err(ClientError::Remote(message)),
        }
        write_frame(&mut stream, &Request::Subscribe).await?;
        let response: Response = read_frame(&mut stream)
            .await?
            .ok_or_else(|| ClientError::Protocol("daemon closed during subscribe".into()))?;
        match response.into_result() {
            Ok(Response::Subscribed) => Ok(Self { stream }),
            Ok(other) => Err(ClientError::Protocol(format!(
                "unexpected subscribe response: {other:?}"
            ))),
            Err(message) => Err(ClientError::Remote(message)),
        }
    }

    pub async fn next(&mut self) -> Result<Option<crate::proto::Event>, ClientError> {
        Ok(read_frame(&mut self.stream).await?)
    }
}
