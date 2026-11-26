//! Small synchronous-looking client used by the GUI and tests.

use std::path::Path;

use tokio::net::UnixStream;

use crate::frame::{read_frame, write_frame, FrameError};
use crate::proto::{Request, Response};
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

pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let mut stream = UnixStream::connect(path).await?;
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

pub struct EventStream {
    stream: UnixStream,
}

impl EventStream {
    pub async fn subscribe(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let mut stream = UnixStream::connect(path).await?;
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
