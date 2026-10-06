//! Images for `symbia_fs_read`: detected by magic bytes, scaled to fit, sent as MCP image content.

use std::io::Cursor;

use image::imageops::FilterType;
use image::{DynamicImage, ImageFormat, ImageReader};

/// Long edge an image is scaled down to unless `full` is set.
pub const LONG_EDGE: u32 = 1568;
/// Hard limits on the image sent, `full` or not.
pub const EDGE_MAX: u32 = 8000;
pub const BYTES_MAX: usize = 5 * 1024 * 1024;
const JPEG_QUALITY: u8 = 85;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Png,
    Jpeg,
    Gif,
    Webp,
    Tiff,
    Bmp,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Gif => "gif",
            Self::Webp => "webp",
            Self::Tiff => "tiff",
            Self::Bmp => "bmp",
        }
    }

    pub fn media(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
            Self::Tiff => "image/tiff",
            Self::Bmp => "image/bmp",
        }
    }

    fn image_format(self) -> ImageFormat {
        match self {
            Self::Png => ImageFormat::Png,
            Self::Jpeg => ImageFormat::Jpeg,
            Self::Gif => ImageFormat::Gif,
            Self::Webp => ImageFormat::WebP,
            Self::Tiff => ImageFormat::Tiff,
            Self::Bmp => ImageFormat::Bmp,
        }
    }

    /// Sent unchanged when it already fits; TIFF and BMP always become PNG.
    fn passes_through(self) -> bool {
        matches!(self, Self::Png | Self::Jpeg | Self::Gif | Self::Webp)
    }

    /// The format a re-encoded image goes out in: JPEG for photos, PNG for the rest.
    fn reencoded(self) -> Self {
        match self {
            Self::Jpeg | Self::Webp => Self::Jpeg,
            _ => Self::Png,
        }
    }
}

/// What the first bytes of a file say it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniff {
    Image(Format),
    Heic,
    Other,
}

/// Bytes [`sniff`] needs.
pub const SNIFF_BYTES: usize = 12;

pub fn sniff(head: &[u8]) -> Sniff {
    let starts = |m: &[u8]| head.starts_with(m);
    if starts(b"\x89PNG\r\n\x1a\n") {
        Sniff::Image(Format::Png)
    } else if starts(&[0xFF, 0xD8, 0xFF]) {
        Sniff::Image(Format::Jpeg)
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        Sniff::Image(Format::Gif)
    } else if head.len() >= 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        Sniff::Image(Format::Webp)
    } else if starts(b"II*\0") || starts(b"MM\0*") {
        Sniff::Image(Format::Tiff)
    } else if starts(b"BM") && head.len() >= 6 {
        Sniff::Image(Format::Bmp)
    } else if head.len() >= 12
        && &head[4..8] == b"ftyp"
        && matches!(&head[8..12], b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis" | b"hevm" | b"hevs" | b"mif1" | b"msf1")
    {
        Sniff::Heic
    } else {
        Sniff::Other
    }
}

/// The image as it will be sent.
pub struct Sent {
    pub format: Format,
    pub width: u32,
    pub height: u32,
    pub sent_format: Format,
    pub sent_width: u32,
    pub sent_height: u32,
    pub bytes: Vec<u8>,
}

/// `(w, h)` scaled so the long edge is `edge`, never up, each side at least 1.
fn fit(w: u32, h: u32, edge: u32) -> (u32, u32) {
    let long = w.max(h);
    if long <= edge {
        return (w, h);
    }
    let scale = |s: u32| u32::try_from((u64::from(s) * u64::from(edge) + u64::from(long) / 2) / u64::from(long)).unwrap_or(1).max(1);
    (scale(w), scale(h))
}

fn encode(img: &DynamicImage, format: Format) -> Result<Vec<u8>, String> {
    let mut out = Cursor::new(Vec::new());
    match format {
        Format::Jpeg => {
            let rgb = DynamicImage::ImageRgb8(img.to_rgb8());
            let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY);
            rgb.write_with_encoder(enc).map_err(|e| format!("jpeg encode: {e}"))?;
        }
        _ => {
            // PNG takes 8- and 16-bit integer pixels; anything else goes to 8-bit RGBA.
            let png = match img {
                DynamicImage::ImageLuma8(_)
                | DynamicImage::ImageLumaA8(_)
                | DynamicImage::ImageRgb8(_)
                | DynamicImage::ImageRgba8(_)
                | DynamicImage::ImageLuma16(_)
                | DynamicImage::ImageLumaA16(_)
                | DynamicImage::ImageRgb16(_)
                | DynamicImage::ImageRgba16(_) => img.clone(),
                _ => DynamicImage::ImageRgba8(img.to_rgba8()),
            };
            png.write_to(&mut out, ImageFormat::Png).map_err(|e| format!("png encode: {e}"))?;
        }
    }
    Ok(out.into_inner())
}

/// Decode `data` and make the image to send: unchanged when it fits, else scaled (Lanczos3)
/// to a long edge of 1,568 px (8,000 with `full`) and re-encoded, then scaled further until
/// it is at most 5 MB.
pub fn prepare(data: &[u8], format: Format, full: bool) -> Result<Sent, String> {
    let img = ImageReader::with_format(Cursor::new(data), format.image_format())
        .decode()
        .map_err(|e| format!("cannot decode {} image: {e}", format.name()))?;
    let (width, height) = (img.width(), img.height());
    let edge = if full { EDGE_MAX } else { LONG_EDGE };
    if format.passes_through() && width.max(height) <= edge && data.len() <= BYTES_MAX {
        return Ok(Sent { format, width, height, sent_format: format, sent_width: width, sent_height: height, bytes: data.to_vec() });
    }
    let sent_format = format.reencoded();
    let mut long = width.max(height).min(edge);
    loop {
        let (w, h) = fit(width, height, long);
        let scaled = if (w, h) == (width, height) { img.clone() } else { img.resize_exact(w, h, FilterType::Lanczos3) };
        let bytes = encode(&scaled, sent_format)?;
        if bytes.len() <= BYTES_MAX {
            return Ok(Sent { format, width, height, sent_format, sent_width: w, sent_height: h, bytes });
        }
        if long == 1 {
            return Err(format!("cannot fit the image in {BYTES_MAX} bytes"));
        }
        // Encoded size goes roughly with area; aim a little under the limit.
        let ratio = (BYTES_MAX as f64 / bytes.len() as f64).sqrt() * 0.9;
        long = ((f64::from(long) * ratio.min(0.9)) as u32).max(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, Rgba};

    pub fn png(w: u32, h: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(w, h, |x, y| Rgba([(x % 256) as u8, (y % 256) as u8, 128, 255]));
        let mut out = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(img).write_to(&mut out, ImageFormat::Png).unwrap();
        out.into_inner()
    }

    fn noise(w: u32, h: u32) -> DynamicImage {
        let mut s: u32 = 0x1234_5678;
        DynamicImage::ImageRgb8(ImageBuffer::from_fn(w, h, |_, _| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            let b = s.to_le_bytes();
            Rgb([b[0], b[1], b[2]])
        }))
    }

    #[test]
    fn sniff_reads_magic_bytes_not_names() {
        assert_eq!(sniff(&png(2, 2)), Sniff::Image(Format::Png));
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0]), Sniff::Image(Format::Jpeg));
        assert_eq!(sniff(b"GIF89a\x01\x00"), Sniff::Image(Format::Gif));
        assert_eq!(sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 "), Sniff::Image(Format::Webp));
        assert_eq!(sniff(b"II*\x00\x08\x00"), Sniff::Image(Format::Tiff));
        assert_eq!(sniff(b"MM\x00*\x00\x00"), Sniff::Image(Format::Tiff));
        assert_eq!(sniff(b"BM\x00\x00\x00\x00"), Sniff::Image(Format::Bmp));
        assert_eq!(sniff(b"\x00\x00\x00\x18ftypheic"), Sniff::Heic);
        assert_eq!(sniff(b"\x00\x00\x00\x18ftypmp42"), Sniff::Other);
        assert_eq!(sniff(b"hello"), Sniff::Other);
        assert_eq!(sniff(b"BM"), Sniff::Other, "too short for a bitmap");
    }

    #[test]
    fn fit_scales_the_long_edge() {
        assert_eq!(fit(4000, 3000, 1568), (1568, 1176));
        assert_eq!(fit(3000, 4000, 1568), (1176, 1568));
        assert_eq!(fit(100, 50, 1568), (100, 50));
        assert_eq!(fit(10_000, 1, 1568), (1568, 1));
    }

    #[test]
    fn small_images_pass_through_and_tiff_becomes_png() {
        let p = png(20, 10);
        let s = prepare(&p, Format::Png, false).unwrap();
        assert_eq!((s.sent_format, s.sent_width, s.sent_height), (Format::Png, 20, 10));
        assert_eq!(s.bytes, p);
        let mut tiff = Cursor::new(Vec::new());
        noise(30, 20).write_to(&mut tiff, ImageFormat::Tiff).unwrap();
        let s = prepare(tiff.get_ref(), Format::Tiff, false).unwrap();
        assert_eq!((s.format, s.sent_format, s.sent_width, s.sent_height), (Format::Tiff, Format::Png, 30, 20));
        assert_eq!(sniff(&s.bytes), Sniff::Image(Format::Png));
    }

    #[test]
    fn over_five_megabytes_is_scaled_further() {
        // Noise does not compress: 2000x2000 RGB is about 12 MB as PNG.
        let mut buf = Cursor::new(Vec::new());
        noise(2000, 2000).write_to(&mut buf, ImageFormat::Png).unwrap();
        assert!(buf.get_ref().len() > BYTES_MAX);
        let s = prepare(buf.get_ref(), Format::Png, true).unwrap();
        assert!(s.bytes.len() <= BYTES_MAX, "{}", s.bytes.len());
        assert!(s.sent_width < 2000 && s.sent_width == s.sent_height);
        assert_eq!(s.sent_format, Format::Png);
    }

    #[test]
    fn a_bad_image_is_an_error() {
        let e = prepare(b"\x89PNG\r\n\x1a\nnot really", Format::Png, false).err().unwrap();
        assert!(e.starts_with("cannot decode png image"), "{e}");
    }
}
