//! Framing for DCleaner's future reactivation helper/service channel.
//!
//! This codec performs no IPC, authentication, launch or native change. A frame
//! and its identifiers are untrusted data until a transport authenticates its
//! peer and the service resolves them against its own durable ownership records.
//! The helper retains the original launch arguments locally; this protocol never
//! accepts a client-supplied command, registry path, executable or native state.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{self, Read, Write};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024;
const MAGIC: [u8; 4] = *b"DCLN";
const HEADER_BYTES: usize = 12;
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub request_id: Uuid,
    pub request: HelperRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperRequest {
    QueryReadiness {},
    Reactivate {
        lease_id: Uuid,
        /// Retained across retries; a request ID identifies one exchange only.
        invocation_id: Uuid,
    },
    QueryInvocation {
        invocation_id: Uuid,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub request_id: Uuid,
    pub response: ServiceResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceResponse {
    Readiness {
        service_instance: Uuid,
        state: Readiness,
    },
    Invocation {
        invocation_id: Uuid,
        state: InvocationState,
    },
    Refused {
        reason: Refusal,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Ready,
    RecoveryRequired,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationState {
    Queued,
    Running,
    /// A service must independently verify native state before emitting this.
    VerifiedReenabled,
    Partial,
    Rejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    UnknownLease,
    NotAuthorized,
    ServiceNotReady,
    OwnershipChanged,
    RecoveryRequired,
    RequestConflict,
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    TruncatedHeader,
    TruncatedPayload,
    InvalidMagic,
    UnsupportedVersion(u16),
    UnexpectedKind { expected: u8, received: u8 },
    ReservedBits,
    InvalidLength(u32),
    InvalidIdentifier,
    CorrelationMismatch,
    ResponseMismatch,
    Payload(serde_json::Error),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Optimizer protocol error: {self:?}")
    }
}
impl std::error::Error for ProtocolError {}

/// EOF before any header byte is a disconnected channel. Every partial frame or
/// other error requires closing the channel; do not attempt stream resync.
pub fn read_request(reader: &mut impl Read) -> Result<Option<RequestEnvelope>, ProtocolError> {
    let message: Option<RequestEnvelope> = read_frame(reader, REQUEST_KIND)?;
    if let Some(message) = &message {
        validate_request(message)?;
    }
    Ok(message)
}

/// Correlates the exchange, response variant and invocation. A transport/effect
/// owner must additionally authenticate the peer and retain service identity.
pub fn read_response(
    reader: &mut impl Read,
    expected: &RequestEnvelope,
) -> Result<Option<ResponseEnvelope>, ProtocolError> {
    validate_request(expected)?;
    let message: Option<ResponseEnvelope> = read_frame(reader, RESPONSE_KIND)?;
    if let Some(message) = &message {
        validate_response(message)?;
        if message.request_id != expected.request_id {
            return Err(ProtocolError::CorrelationMismatch);
        }
        match (&expected.request, &message.response) {
            (_, ServiceResponse::Refused { .. })
            | (HelperRequest::QueryReadiness {}, ServiceResponse::Readiness { .. }) => {}
            (
                HelperRequest::Reactivate { invocation_id, .. }
                | HelperRequest::QueryInvocation { invocation_id },
                ServiceResponse::Invocation {
                    invocation_id: returned,
                    ..
                },
            ) if invocation_id == returned => {}
            _ => return Err(ProtocolError::ResponseMismatch),
        }
    }
    Ok(message)
}

/// Successful encoding is not peer receipt, task acceptance or native completion.
/// Flush policy and bounded waits belong to the transport/effect owner.
pub fn write_request(
    writer: &mut impl Write,
    message: &RequestEnvelope,
) -> Result<(), ProtocolError> {
    validate_request(message)?;
    write_frame(writer, REQUEST_KIND, message)
}

pub fn write_response(
    writer: &mut impl Write,
    message: &ResponseEnvelope,
) -> Result<(), ProtocolError> {
    validate_response(message)?;
    write_frame(writer, RESPONSE_KIND, message)
}

fn non_nil(id: Uuid) -> Result<(), ProtocolError> {
    if id.is_nil() {
        Err(ProtocolError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn validate_request(message: &RequestEnvelope) -> Result<(), ProtocolError> {
    non_nil(message.request_id)?;
    match message.request {
        HelperRequest::QueryReadiness {} => Ok(()),
        HelperRequest::Reactivate {
            lease_id,
            invocation_id,
        } => {
            non_nil(lease_id)?;
            non_nil(invocation_id)
        }
        HelperRequest::QueryInvocation { invocation_id } => non_nil(invocation_id),
    }
}

fn validate_response(message: &ResponseEnvelope) -> Result<(), ProtocolError> {
    non_nil(message.request_id)?;
    match message.response {
        ServiceResponse::Readiness {
            service_instance, ..
        } => non_nil(service_instance),
        ServiceResponse::Invocation { invocation_id, .. } => non_nil(invocation_id),
        ServiceResponse::Refused { .. } => Ok(()),
    }
}

fn read_frame<T: DeserializeOwned>(
    reader: &mut impl Read,
    expected_kind: u8,
) -> Result<Option<T>, ProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ProtocolError::Io(error)),
        }
    }
    read_rest(reader, &mut header[1..], true)?;
    if header[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    if header[6] != expected_kind {
        return Err(ProtocolError::UnexpectedKind {
            expected: expected_kind,
            received: header[6],
        });
    }
    if header[7] != 0 {
        return Err(ProtocolError::ReservedBits);
    }
    let length = u32::from_le_bytes(header[8..12].try_into().expect("fixed header slice"));
    if length == 0 || length as usize > MAX_PAYLOAD_BYTES {
        return Err(ProtocolError::InvalidLength(length));
    }
    let mut payload = vec![0; length as usize];
    read_rest(reader, &mut payload, false)?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(ProtocolError::Payload)
}

fn read_rest(reader: &mut impl Read, bytes: &mut [u8], header: bool) -> Result<(), ProtocolError> {
    reader.read_exact(bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            if header {
                ProtocolError::TruncatedHeader
            } else {
                ProtocolError::TruncatedPayload
            }
        } else {
            ProtocolError::Io(error)
        }
    })
}

fn write_frame(
    writer: &mut impl Write,
    kind: u8,
    message: &impl Serialize,
) -> Result<(), ProtocolError> {
    let payload = serde_json::to_vec(message).map_err(ProtocolError::Payload)?;
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ProtocolError::InvalidLength(
            u32::try_from(payload.len()).unwrap_or(u32::MAX),
        ));
    }
    let mut header = [0; HEADER_BYTES];
    header[..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    header[6] = kind;
    header[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    writer.write_all(&header).map_err(ProtocolError::Io)?;
    writer.write_all(&payload).map_err(ProtocolError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn request() -> RequestEnvelope {
        RequestEnvelope {
            request_id: Uuid::from_u128(1),
            request: HelperRequest::Reactivate {
                lease_id: Uuid::from_u128(2),
                invocation_id: Uuid::from_u128(3),
            },
        }
    }

    fn encoded() -> Vec<u8> {
        let mut output = Vec::new();
        write_request(&mut output, &request()).unwrap();
        output
    }

    fn raw_payload(payload: &[u8]) -> Vec<u8> {
        let mut frame = encoded()[..HEADER_BYTES].to_vec();
        frame[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn fragmented_reads_preserve_frame_boundaries_and_invocation_identity() {
        struct Fragmented(Cursor<Vec<u8>>);
        impl Read for Fragmented {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let limit = buffer.len().min(1);
                self.0.read(&mut buffer[..limit])
            }
        }
        let mut two = encoded();
        two.extend(encoded());
        let mut reader = Fragmented(Cursor::new(two));
        assert_eq!(read_request(&mut reader).unwrap(), Some(request()));
        assert_eq!(read_request(&mut reader).unwrap(), Some(request()));
        assert!(read_request(&mut reader).unwrap().is_none());
    }

    #[test]
    fn truncation_is_distinct_from_clean_disconnect_at_every_boundary() {
        let frame = encoded();
        assert!(
            read_request(&mut Cursor::new(&frame[..0]))
                .unwrap()
                .is_none()
        );
        for split in 1..frame.len() {
            let error = read_request(&mut Cursor::new(&frame[..split])).unwrap_err();
            assert!(if split < HEADER_BYTES {
                matches!(error, ProtocolError::TruncatedHeader)
            } else {
                matches!(error, ProtocolError::TruncatedPayload)
            });
        }
    }

    #[test]
    fn rejected_headers_do_not_consume_or_allocate_declared_payload() {
        let original = encoded();
        for case in 0..6 {
            let mut frame = original.clone();
            match case {
                0 => frame[0] ^= 1,
                1 => frame[4..6].copy_from_slice(&2_u16.to_le_bytes()),
                2 => frame[6] = RESPONSE_KIND,
                3 => frame[7] = 1,
                4 => frame[8..12].copy_from_slice(&0_u32.to_le_bytes()),
                _ => frame[8..12].copy_from_slice(&u32::MAX.to_le_bytes()),
            }
            let mut reader = Cursor::new(frame);
            assert!(read_request(&mut reader).is_err());
            assert_eq!(reader.position(), HEADER_BYTES as u64);
        }
    }

    #[test]
    fn schema_rejects_unknown_duplicate_and_path_bearing_fields() {
        let id = Uuid::from_u128(1);
        for json in [
            format!(
                r#"{{"request_id":"{id}","request_id":"{id}","request":{{"operation":"query_readiness"}}}}"#
            ),
            format!(
                r#"{{"request_id":"{id}","request":{{"operation":"query_readiness","path":"arbitrary"}}}}"#
            ),
            format!(r#"{{"request_id":"{id}","request":{{"operation":"run_command"}}}}"#),
            format!(
                r#"{{"request_id":"{id}","request":{{"operation":"query_readiness"}},"extra":true}}"#
            ),
        ] {
            assert!(matches!(
                read_request(&mut Cursor::new(raw_payload(json.as_bytes()))),
                Err(ProtocolError::Payload(_))
            ));
        }
    }

    #[test]
    fn nil_identifiers_cannot_be_encoded_or_accepted() {
        let mut message = request();
        message.request_id = Uuid::nil();
        let mut output = Vec::new();
        assert!(matches!(
            write_request(&mut output, &message),
            Err(ProtocolError::InvalidIdentifier)
        ));
        assert!(output.is_empty());
        let json = serde_json::to_vec(&message).unwrap();
        assert!(matches!(
            read_request(&mut Cursor::new(raw_payload(&json))),
            Err(ProtocolError::InvalidIdentifier)
        ));
        message = request();
        message.request = HelperRequest::QueryInvocation {
            invocation_id: Uuid::nil(),
        };
        assert!(write_request(&mut output, &message).is_err());
    }

    #[test]
    fn responses_must_match_direction_and_request_correlation() {
        let response = ResponseEnvelope {
            request_id: request().request_id,
            response: ServiceResponse::Invocation {
                invocation_id: Uuid::from_u128(3),
                state: InvocationState::Running,
            },
        };
        let mut bytes = Vec::new();
        write_response(&mut bytes, &response).unwrap();
        assert_eq!(
            read_response(&mut Cursor::new(&bytes), &request()).unwrap(),
            Some(response)
        );
        let mut wrong = request();
        wrong.request_id = Uuid::from_u128(99);
        assert!(matches!(
            read_response(&mut Cursor::new(&bytes), &wrong),
            Err(ProtocolError::CorrelationMismatch)
        ));
        wrong = request();
        wrong.request = HelperRequest::QueryInvocation {
            invocation_id: Uuid::from_u128(99),
        };
        assert!(matches!(
            read_response(&mut Cursor::new(&bytes), &wrong),
            Err(ProtocolError::ResponseMismatch)
        ));
        wrong.request = HelperRequest::QueryReadiness {};
        assert!(matches!(
            read_response(&mut Cursor::new(&bytes), &wrong),
            Err(ProtocolError::ResponseMismatch)
        ));
        assert!(matches!(
            read_request(&mut Cursor::new(&bytes)),
            Err(ProtocolError::UnexpectedKind { .. })
        ));
        assert!(matches!(
            read_response(&mut Cursor::new(encoded()), &request()),
            Err(ProtocolError::UnexpectedKind { .. })
        ));
    }

    #[test]
    fn partial_writes_and_transport_failures_are_not_reported_as_delivery() {
        struct FailingWriter(Vec<u8>);
        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0.len() >= HEADER_BYTES + 5 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture"));
                }
                let count = bytes.len().min(1);
                self.0.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = FailingWriter(Vec::new());
        assert!(matches!(
            write_request(&mut writer, &request()),
            Err(ProtocolError::Io(_))
        ));
        assert!(matches!(
            read_request(&mut Cursor::new(writer.0)),
            Err(ProtocolError::TruncatedPayload)
        ));
    }
}
