//! Lossless invocation data, never executable selection or effect authority.
use super::ProtocolError;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use zeroize::Zeroizing;

const MAX_TEXT: usize = 32_766;
const MAX_ENVIRONMENT: usize = 512 * 1024;

#[derive(Clone, Eq, PartialEq)]
struct Units(Zeroizing<Vec<u16>>);
impl Serialize for Units {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_slice().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Units {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Bounded;
        impl<'de> de::Visitor<'de> for Bounded {
            type Value = Units;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded array of original UTF-16 units")
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Units, A::Error> {
                let mut units = Zeroizing::new(Vec::new());
                while let Some(unit) = sequence.next_element::<u16>()? {
                    if units.len() == MAX_ENVIRONMENT {
                        return Err(de::Error::custom("Original context exceeds its unit bound"));
                    }
                    units.push(unit);
                }
                Ok(Units(units))
            }
        }
        deserializer.deserialize_seq(Bounded)
    }
}

/// Helper-origin data. No application path, token, inherited handles, startup
/// flags, hook state or launch authority can be supplied through this object.
/// Debug is redacted and owned unit buffers are zeroized on drop. This is not
/// a guarantee that the allocator, OS pipe buffers or other process copies wipe.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalContext {
    command: Units,
    directory: Units,
    environment: Units,
    show_window: Option<u16>,
}
impl fmt::Debug for OriginalContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalContext { <redacted> }")
    }
}
impl OriginalContext {
    pub fn new(
        command: Vec<u16>,
        directory: Vec<u16>,
        environment: Vec<u16>,
        show_window: Option<u16>,
    ) -> Result<Self, ProtocolError> {
        let context = Self {
            command: Units(Zeroizing::new(command)),
            directory: Units(Zeroizing::new(directory)),
            environment: Units(Zeroizing::new(environment)),
            show_window,
        };
        context.validate()?;
        Ok(context)
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let text =
            |units: &[u16]| !units.is_empty() && units.len() <= MAX_TEXT && !units.contains(&0);
        if !text(&self.command.0)
            || !text(&self.directory.0)
            || !environment_valid(&self.environment.0)
            || self
                .show_window
                .is_some_and(|value| !matches!(value, 0..=9 | 11))
        {
            return Err(ProtocolError::InvalidOriginalContext);
        }
        Ok(())
    }
    pub fn command(&self) -> &[u16] {
        &self.command.0
    }
    pub fn directory(&self) -> &[u16] {
        &self.directory.0
    }
    pub fn environment(&self) -> &[u16] {
        &self.environment.0
    }
    pub fn show_window(&self) -> Option<u16> {
        self.show_window
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self::new(
            "\"C:\\Fixture\\original.exe\" --synthetic"
                .encode_utf16()
                .collect(),
            "C:\\Fixture".encode_utf16().collect(),
            vec![61, 67, 58, 61, 67, 58, 92, 0, 88, 61, 0xd800, 0, 0],
            Some(0),
        )
        .unwrap()
    }
}

fn environment_valid(value: &[u16]) -> bool {
    if value.len() < 2 || value.len() > MAX_ENVIRONMENT || !value.ends_with(&[0, 0]) {
        return false;
    }
    if value == [0, 0] {
        return true;
    }
    let mut at = 0;
    while at < value.len() - 1 {
        let Some(length) = value[at..].iter().position(|unit| *unit == 0) else {
            return false;
        };
        let entry = &value[at..at + length];
        let start = usize::from(entry.first() == Some(&(b'=' as u16)));
        if entry.len() <= start
            || !entry[start..]
                .iter()
                .position(|unit| *unit == b'=' as u16)
                .is_some_and(|p| p > 0)
        {
            return false;
        }
        at += length + 1;
    }
    at == value.len() - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer_protocol::*;
    use std::io::Cursor;

    #[test]
    fn opaque_context_roundtrips_above_old_frame_bound_without_executable_authority() {
        let mut original = OriginalContext::fixture();
        original.command.0.extend([0xd800, 32, 34, 92, 34]);
        let mut environment = vec![b'X' as u16, b'=' as u16];
        environment.extend(std::iter::repeat_n(0xdfff, 16_000));
        environment.extend([0, 0]);
        original.environment = Units(Zeroizing::new(environment));
        let expected = RequestEnvelope {
            request_id: uuid::Uuid::new_v4(),
            request: HelperRequest::Reactivate {
                lease_id: uuid::Uuid::new_v4(),
                invocation_id: uuid::Uuid::new_v4(),
                original: Box::new(original),
            },
        };
        let mut frame = Vec::new();
        write_request(&mut frame, &expected).unwrap();
        assert!(frame.len() > 8 * 1024 && frame.len() < MAX_PAYLOAD_BYTES);
        assert_eq!(
            read_request(&mut Cursor::new(frame)).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn maximum_original_context_fits_the_new_frame_and_old_version_refuses_before_payload() {
        let context = OriginalContext::new(
            vec![0xd800; MAX_TEXT],
            vec![0xdfff; MAX_TEXT],
            {
                let mut environment = vec![0xdfff; MAX_ENVIRONMENT];
                environment[0] = 65;
                environment[1] = 61;
                environment[MAX_ENVIRONMENT - 2..].copy_from_slice(&[0, 0]);
                environment
            },
            Some(11),
        )
        .unwrap();
        let request = RequestEnvelope {
            request_id: uuid::Uuid::new_v4(),
            request: HelperRequest::Reactivate {
                lease_id: uuid::Uuid::new_v4(),
                invocation_id: uuid::Uuid::new_v4(),
                original: Box::new(context),
            },
        };
        let mut frame = Vec::new();
        write_request(&mut frame, &request).unwrap();
        assert!(frame.len() <= MAX_PAYLOAD_BYTES + 12);
        assert_eq!(
            read_request(&mut Cursor::new(&frame)).unwrap(),
            Some(request)
        );
        frame[4..6].copy_from_slice(&1u16.to_le_bytes());
        let mut reader = Cursor::new(frame);
        assert!(matches!(
            read_request(&mut reader),
            Err(ProtocolError::UnsupportedVersion(1))
        ));
        assert_eq!(reader.position(), 12);
    }

    #[test]
    fn decoded_context_validation_and_small_response_bound_are_enforced_before_use() {
        let request = RequestEnvelope {
            request_id: uuid::Uuid::new_v4(),
            request: HelperRequest::Reactivate {
                lease_id: uuid::Uuid::new_v4(),
                invocation_id: uuid::Uuid::new_v4(),
                original: Box::new(OriginalContext::fixture()),
            },
        };
        let mut invalid = serde_json::to_value(&request).unwrap();
        invalid["request"]["original"]["environment"] = serde_json::json!([65, 0, 0]);
        let mut bytes = Vec::new();
        super::super::write_frame(&mut bytes, 1, &invalid).unwrap();
        assert!(matches!(
            read_request(&mut Cursor::new(bytes)),
            Err(ProtocolError::InvalidOriginalContext)
        ));
        let mut missing = serde_json::to_value(&request).unwrap();
        missing["request"]
            .as_object_mut()
            .unwrap()
            .remove("original");
        let mut bytes = Vec::new();
        super::super::write_frame(&mut bytes, 1, &missing).unwrap();
        assert!(matches!(
            read_request(&mut Cursor::new(bytes)),
            Err(ProtocolError::Payload(_))
        ));
        let mut response = Vec::new();
        write_response(
            &mut response,
            &ResponseEnvelope {
                request_id: request.request_id,
                response: ServiceResponse::Refused {
                    reason: Refusal::ServiceNotReady,
                },
            },
        )
        .unwrap();
        response[8..12].copy_from_slice(&(8193u32).to_le_bytes());
        let mut reader = Cursor::new(response);
        assert!(matches!(
            read_response(&mut reader, &request),
            Err(ProtocolError::InvalidLength(8193))
        ));
        assert_eq!(reader.position(), 12);
    }

    #[test]
    fn context_refuses_malformed_units_terminators_show_state_and_excess_without_echoing_secrets() {
        let valid = OriginalContext::fixture();
        assert!(!format!("{valid:?}").contains("original.exe"));
        assert!(!format!("{valid:?}").contains("Fixture"));
        for field in 0..5 {
            let mut invalid = valid.clone();
            match field {
                0 => invalid.command.0.push(0),
                1 => invalid.directory.0.clear(),
                2 => invalid.environment.0.extend([65, 0, 0]),
                3 => invalid.show_window = Some(10),
                _ => invalid.command.0.resize(MAX_TEXT + 1, 65),
            }
            assert!(matches!(
                invalid.validate(),
                Err(ProtocolError::InvalidOriginalContext)
            ));
        }
        let encoded = serde_json::to_value(&valid).unwrap();
        let mut extra = encoded.clone();
        extra["application"] = serde_json::json!("arbitrary.exe");
        assert!(serde_json::from_value::<OriginalContext>(extra).is_err());
        let mut excessive = encoded;
        excessive["environment"] = serde_json::json!(vec![0; MAX_ENVIRONMENT + 1]);
        assert!(serde_json::from_value::<OriginalContext>(excessive).is_err());
    }
}
