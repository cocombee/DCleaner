use std::fmt;
use std::io::Cursor;

/// Sampled exactly from the user's supplied brand swatch.
pub const BLUE: eframe::egui::Color32 = eframe::egui::Color32::from_rgb(57, 153, 217);

const ICON_PNG: &[u8] = include_bytes!("../assets/brand/dcleaner-dc.png");
const ICON_ICO: &[u8] = include_bytes!("../assets/brand/dcleaner-dc.ico");
const ICON_WIDTH: u32 = 1024;
const ICON_HEIGHT: u32 = 1024;

#[derive(Debug)]
pub enum BrandError {
    Decode(png::DecodingError),
    InvalidDimensions {
        width: u32,
        height: u32,
    },
    UnsupportedFormat {
        color_type: png::ColorType,
        bit_depth: png::BitDepth,
    },
    InvalidBuffer,
    InvalidIconDirectory,
}

impl fmt::Display for BrandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "could not decode application icon: {error}"),
            Self::InvalidDimensions { width, height } => {
                write!(
                    formatter,
                    "unexpected application icon dimensions: {width}x{height}"
                )
            }
            Self::UnsupportedFormat {
                color_type,
                bit_depth,
            } => write!(
                formatter,
                "unsupported application icon PNG format: {color_type:?} at {bit_depth:?}"
            ),
            Self::InvalidBuffer => {
                formatter.write_str("application icon PNG has an invalid RGBA buffer")
            }
            Self::InvalidIconDirectory => {
                formatter.write_str("application icon lacks a unique bounded PNG frame")
            }
        }
    }
}

impl std::error::Error for BrandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

pub fn icon() -> Result<eframe::egui::IconData, BrandError> {
    decode_icon(ICON_PNG, ICON_WIDTH, ICON_HEIGHT)
}

/// Use the existing Windows-sized artwork instead of converting the 1024-pixel
/// in-app logo into a native HICON. No resampling or new asset is introduced.
pub fn windows_icon() -> Result<eframe::egui::IconData, BrandError> {
    decode_icon(ico_png_frame(ICON_ICO, 256)?, 256, 256)
}

fn ico_png_frame(bytes: &[u8], dimension: u32) -> Result<&[u8], BrandError> {
    let invalid = || BrandError::InvalidIconDirectory;
    let header = bytes.get(..6).ok_or_else(invalid)?;
    if header[..4] != [0, 0, 1, 0] {
        return Err(invalid());
    }
    let count = usize::from(u16::from_le_bytes([header[4], header[5]]));
    let directory_end = count
        .checked_mul(16)
        .and_then(|n| n.checked_add(6))
        .ok_or_else(invalid)?;
    if count == 0 || bytes.get(..directory_end).is_none() {
        return Err(invalid());
    }
    let mut selected = None;
    for entry in bytes[6..directory_end].chunks_exact(16) {
        let width = if entry[0] == 0 {
            256
        } else {
            u32::from(entry[0])
        };
        let height = if entry[1] == 0 {
            256
        } else {
            u32::from(entry[1])
        };
        if width != dimension || height != dimension {
            continue;
        }
        if selected.is_some() {
            return Err(invalid());
        }
        let length = u32::from_le_bytes(entry[8..12].try_into().map_err(|_| invalid())?) as usize;
        let offset = u32::from_le_bytes(entry[12..16].try_into().map_err(|_| invalid())?) as usize;
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        if offset < directory_end {
            return Err(invalid());
        }
        let png = bytes.get(offset..end).ok_or_else(invalid)?;
        if !png.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(invalid());
        }
        selected = Some(png);
    }
    selected.ok_or_else(invalid)
}

fn decode_icon(
    encoded: &[u8],
    width: u32,
    height: u32,
) -> Result<eframe::egui::IconData, BrandError> {
    let decoder = png::Decoder::new(Cursor::new(encoded));
    let mut reader = decoder.read_info().map_err(BrandError::Decode)?;
    let header = reader.info();
    if header.width != width || header.height != height {
        return Err(BrandError::InvalidDimensions {
            width: header.width,
            height: header.height,
        });
    }
    if header.color_type != png::ColorType::Rgba || header.bit_depth != png::BitDepth::Eight {
        return Err(BrandError::UnsupportedFormat {
            color_type: header.color_type,
            bit_depth: header.bit_depth,
        });
    }

    let size = reader
        .output_buffer_size()
        .ok_or(BrandError::InvalidBuffer)?;
    let expected_size = (width as usize)
        .checked_mul(height as usize)
        .and_then(|n| n.checked_mul(4))
        .ok_or(BrandError::InvalidBuffer)?;
    if size != expected_size {
        return Err(BrandError::InvalidBuffer);
    }
    let mut rgba = vec![0; size];
    let frame = reader.next_frame(&mut rgba).map_err(BrandError::Decode)?;
    if frame.width != width
        || frame.height != height
        || frame.color_type != png::ColorType::Rgba
        || frame.bit_depth != png::BitDepth::Eight
        || frame.buffer_size() != expected_size
    {
        return Err(BrandError::InvalidBuffer);
    }
    rgba.truncate(frame.buffer_size());
    Ok(eframe::egui::IconData {
        rgba,
        width: frame.width,
        height: frame.height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_icon_decodes_to_expected_rgba_dimensions() {
        let icon = icon().expect("the checked-in application icon should decode");
        assert_eq!((icon.width, icon.height), (ICON_WIDTH, ICON_HEIGHT));
        assert_eq!(icon.rgba.len(), (ICON_WIDTH * ICON_HEIGHT * 4) as usize);
    }

    #[test]
    fn windows_frame_preserves_transparent_blue_art_at_native_size() {
        let native = windows_icon().expect("the bundled native frame should decode");
        assert_eq!((native.width, native.height), (256, 256));
        assert_eq!(native.rgba.len(), 256 * 256 * 4);
        assert_eq!(native.rgba[3], 0);
        assert_eq!(
            native.rgba[((128 * 256 + 128) * 4) + 3],
            0,
            "DC letter gap must stay transparent"
        );
        let mut transparent = 0;
        let mut antialiased = 0;
        let mut branded = 0;
        for pixel in native.rgba.chunks_exact(4) {
            if pixel[3] == 0 {
                transparent += 1;
            } else if pixel[3] < 255 {
                antialiased += 1;
            } else if pixel[..3] == [BLUE.r(), BLUE.g(), BLUE.b()] {
                branded += 1;
            }
        }
        assert!(
            transparent > 1000 && branded > 1000 && antialiased > 100,
            "native artwork must not become blank, opaque or lose its edge alpha"
        );
    }

    #[test]
    fn ico_frame_refuses_truncation_ambiguity_overlapping_and_mislabeled_payloads() {
        fn fixture(payload: &[u8], count: u16) -> Vec<u8> {
            let end = 6 + usize::from(count) * 16;
            let mut bytes = vec![0; end];
            bytes[..4].copy_from_slice(&[0, 0, 1, 0]);
            bytes[4..6].copy_from_slice(&count.to_le_bytes());
            for i in 0..usize::from(count) {
                let at = 6 + i * 16;
                bytes[at + 8..at + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
                bytes[at + 12..at + 16].copy_from_slice(&(end as u32).to_le_bytes());
            }
            bytes.extend_from_slice(payload);
            bytes
        }
        let payload = ico_png_frame(ICON_ICO, 256).unwrap();
        let valid = fixture(payload, 1);
        assert_eq!(ico_png_frame(&valid, 256).unwrap(), payload);
        let mut cases = vec![
            vec![],
            valid[..5].to_vec(),
            valid[..21].to_vec(),
            fixture(payload, 2),
            fixture(&[0; 8], 1),
        ];
        for (at, replacement) in [
            (2, vec![2, 0]),
            (4, vec![0, 0]),
            (4, u16::MAX.to_le_bytes().to_vec()),
            (14, u32::MAX.to_le_bytes().to_vec()),
            (18, 0u32.to_le_bytes().to_vec()),
            (18, u32::MAX.to_le_bytes().to_vec()),
            (6, vec![32, 32]),
        ] {
            let mut bad = valid.clone();
            bad[at..at + replacement.len()].copy_from_slice(&replacement);
            cases.push(bad);
        }
        for bytes in cases {
            assert!(matches!(
                ico_png_frame(&bytes, 256),
                Err(BrandError::InvalidIconDirectory)
            ));
        }
        let wrong_dimensions = fixture(ICON_PNG, 1);
        assert!(matches!(
            decode_icon(ico_png_frame(&wrong_dimensions, 256).unwrap(), 256, 256),
            Err(BrandError::InvalidDimensions {
                width: 1024,
                height: 1024
            })
        ));
    }

    #[test]
    fn windows_icon_contains_32_and_256_pixel_images() {
        assert!(ICON_ICO.len() >= 6);
        assert_eq!(u16::from_le_bytes([ICON_ICO[0], ICON_ICO[1]]), 0);
        assert_eq!(u16::from_le_bytes([ICON_ICO[2], ICON_ICO[3]]), 1);
        let count = usize::from(u16::from_le_bytes([ICON_ICO[4], ICON_ICO[5]]));
        assert!(count > 0);
        assert!(ICON_ICO.len() >= 6 + count * 16);

        let mut has_32 = false;
        let mut has_256 = false;
        for index in 0..count {
            let offset = 6 + index * 16;
            let width = if ICON_ICO[offset] == 0 {
                256
            } else {
                u32::from(ICON_ICO[offset])
            };
            let height = if ICON_ICO[offset + 1] == 0 {
                256
            } else {
                u32::from(ICON_ICO[offset + 1])
            };
            has_32 |= width == 32 && height == 32;
            has_256 |= width == 256 && height == 256;
        }
        assert!(has_32, "Windows icon should contain a 32x32 image");
        assert!(has_256, "Windows icon should contain a 256x256 image");
    }
}
