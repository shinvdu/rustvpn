//! Length-prefixed JSON framing (4-byte big-endian length).

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap for a single frame; prevents a malicious peer from exhausting
/// memory.  Real messages are a few hundred KiB at most.
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("control socket I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("control frame is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("control frame is too large: {0} bytes")]
    TooLarge(usize),
}

pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(body.len()));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(Some(serde_json::from_slice(&body)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Request;

    #[tokio::test]
    async fn round_trip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let request = Request::Kick {
            id: "00".repeat(16),
            reason: "test".into(),
        };
        write_frame(&mut client, &request).await.unwrap();
        let decoded: Request = read_frame(&mut server).await.unwrap().unwrap();
        assert!(matches!(decoded, Request::Kick { .. }));
    }

    #[tokio::test]
    async fn rejects_oversized_length() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&((MAX_FRAME_LEN + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        let error = read_frame::<_, Request>(&mut server).await.unwrap_err();
        assert!(matches!(error, FrameError::TooLarge(_)));
    }
}
