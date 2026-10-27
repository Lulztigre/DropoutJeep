"""Polymorphic payload generator for authorized phishing simulations.

Produces per-recipient unique payload bytes so the same campaign attachment
is not byte-identical across targets. This helps evade signature-based
detection during controlled tests.
"""

import hashlib
import io
import logging
import zipfile

logger = logging.getLogger(__name__)


def _unique_marker(seed: str) -> str:
    """Return a short unique string derived from the recipient seed."""
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"dj-{h}"


def _polymorph_text(content: bytes, seed: str, comment_open: str, comment_close: str) -> bytes:
    """Insert a unique comment into text-based payload content."""
    marker = _unique_marker(seed)
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = content.decode("latin-1", errors="replace")
    injection = f"{comment_open} {marker} {comment_close}"
    # Insert near the beginning after any opening tag or shebang.
    if text.lstrip().startswith("<"):
        idx = text.find(">", 0, 200)
        if idx != -1:
            text = text[: idx + 1] + injection + text[idx + 1 :]
        else:
            text = injection + text
    else:
        text = injection + "\n" + text
    return text.encode("utf-8")


def _polymorph_ooxml(content: bytes, seed: str) -> bytes:
    """Inject a unique custom property into an Office Open XML document."""
    marker = _unique_marker(seed)
    try:
        in_buf = io.BytesIO(content)
        out_buf = io.BytesIO()
        with zipfile.ZipFile(in_buf, "r") as zin, zipfile.ZipFile(
            out_buf, "w", zipfile.ZIP_DEFLATED
        ) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                # Insert marker comment into document.xml / sheet.xml / slide.xml
                if item.filename.endswith(
                    ("document.xml", "worksheet.xml", "slide.xml", "presentation.xml")
                ):
                    try:
                        text = data.decode("utf-8")
                        tag = "<!-- {marker} -->".format(marker=marker)
                        # Place after the first XML declaration or root opening.
                        if text.startswith("<?xml"):
                            end_decl = text.find("?>", 0, 200)
                            if end_decl != -1:
                                text = text[: end_decl + 2] + tag + text[end_decl + 2 :]
                        else:
                            text = tag + text
                        data = text.encode("utf-8")
                    except Exception:
                        pass
                zout.writestr(item, data)
        return out_buf.getvalue()
    except Exception as exc:
        logger.warning("OOXML polymorphism failed: %s", exc)
        return content


def _polymorph_binary(content: bytes, seed: str) -> bytes:
    """Append a unique trailer to binary content.

    The trailer is a benign sequence of bytes that does not affect execution
    for most formats (e.g. ignored data at end of file).
    """
    marker = _unique_marker(seed)
    trailer = f"\n<!-- DJ_MARKER:{marker} -->\n".encode("utf-8")
    return content + trailer


def polymorph_payload(content: bytes, extension: str, seed: str) -> bytes:
    """Return a per-seed variant of the payload content.

    ``seed`` should be the recipient token so each target gets unique bytes.
    """
    ext = (extension or "").lower()
    if ext == "hta":
        return _polymorph_text(content, seed, "<!--", "-->")
    if ext in ("docx", "xlsx", "pptx"):
        return _polymorph_ooxml(content, seed)
    if ext in ("lnk", "bin", "iso", "vhd", "vhdx"):
        return _polymorph_binary(content, seed)
    return _polymorph_binary(content, seed)
