use std::fmt;
use std::io::Cursor;

const ICON_PNG: &[u8] = include_bytes!("../assets/brand/dcleaner.png");
#[cfg(test)]
const ICON_ICO: &[u8] = include_bytes!("../assets/brand/dcleaner.ico");
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
    let decoder = png::Decoder::new(Cursor::new(ICON_PNG));
    let mut reader = decoder.read_info().map_err(BrandError::Decode)?;
    let header = reader.info();
    if header.width != ICON_WIDTH || header.height != ICON_HEIGHT {
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
    let mut rgba = vec![0; size];
    let frame = reader.next_frame(&mut rgba).map_err(BrandError::Decode)?;
    if frame.width != ICON_WIDTH
        || frame.height != ICON_HEIGHT
        || frame.color_type != png::ColorType::Rgba
        || frame.bit_depth != png::BitDepth::Eight
        || frame.buffer_size() != (ICON_WIDTH * ICON_HEIGHT * 4) as usize
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
