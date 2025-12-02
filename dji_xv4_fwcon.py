#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DJI xV4 Firmware Container Tool - Extract and create DJI firmware packages.

OVERVIEW:
    This tool is the primary entry point for analyzing DJI drone firmware. It handles
    the outer "xV4" container format used by DJI to package firmware updates for their
    consumer drone products. The container wraps multiple firmware modules (one for each
    hardware component) along with metadata, checksums, and optional encryption.

    The "xV4" name comes from the 4-byte magic number at the start of these files:
    0x12345678, which when combined with version info, identifies the format. DJI has
    used several versions of this format (201412, 201502, 201507, 201608) with slight
    variations in how versions and metadata are encoded.

    Use this tool FIRST when analyzing any DJI firmware BIN file that starts with the
    xV4 magic bytes. After extraction, the individual modules can be further processed
    with other tools like dji_imah_fwsig.py, amba_fwpak.py, etc.

KEY CONCEPTS:
    - xV4 Container: The outer package format containing multiple firmware modules
    - Module: A single firmware component for a specific target (camera, flight controller, etc.)
    - Target: Hardware component identifier (e.g., m0100=camera, m0306=flight controller)
    - Magic: The 4-byte identifier 0x12345678 at the start of valid firmware files
    - CRC16: Checksum used to verify header integrity (non-standard algorithm)
    - MD5: Checksum used to verify module data integrity
    - AES-128: Encryption used for some modules (type 1 encryption)

USAGE EXAMPLES:
    Extract modules from a DJI firmware package:
        ./dji_xv4_fwcon.py -vv -x -p P3X_FW_V01.08.0080.bin

    Create a firmware package from previously extracted modules:
        ./dji_xv4_fwcon.py -vv -a -p P3X_FW_V01.08.0080_new.bin

    Extract without decrypting encrypted modules:
        ./dji_xv4_fwcon.py -vv -x -c -p P3X_FW_V01.08.0080.bin

WORKFLOW POSITION:
    This tool is Step 1 in firmware analysis:
    
    [DJI Firmware .BIN] --> dji_xv4_fwcon.py (this tool)
         |
         +--> [Module m0100] --> amba_fwpak.py (for Ambarella camera firmware)
         |                            |
         |                            +--> amba_romfs.py (ROMFS partition)
         |                            +--> amba_sys2elf.py (System partition to ELF)
         |
         +--> [Module m0306] --> dji_mvfc_fwpak.py (for encrypted FC)
         |                            |
         |                            +--> arm_bin2elf.py (convert to ELF for disassembly)
         |
         +--> [Module m0801] --> dji_imah_fwsig.py (for IM*H signed modules)
         |
         +--> [Other modules] --> Various processing tools

FILE FORMAT:
    The xV4 container has the following structure:
    
    +---------------------------+
    | FwPkgHeader (64 bytes)    |  Magic, version info, timestamp, entry count
    +---------------------------+
    | FwPkgEntry[0] (52 bytes)  |  First module: target, version, offsets, checksums
    +---------------------------+
    | FwPkgEntry[1] (52 bytes)  |  Second module...
    +---------------------------+
    | ... more entries ...      |
    +---------------------------+
    | Header CRC16 (2 bytes)    |  Checksum of header + all entries
    +---------------------------+
    | Module 0 Data             |  Actual firmware binary for first module
    +---------------------------+
    | Module 1 Data             |  Actual firmware binary for second module
    +---------------------------+
    | ... more module data ...  |
    +---------------------------+

DEPENDENCIES:
    - pycryptodome: Required for AES-128 decryption/encryption of encrypted modules

AUTHORS:
    Mefistotelis, Original Gangsters

LICENSE:
    GPL-3.0 - See LICENSE file for details
"""

# Copyright (C) 2016,2017 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2018 Original Gangsters <https://dji-rev.slack.com/>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__version__ = "0.3.2"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import re
import os
import hashlib
import binascii
import argparse
import configparser
import itertools
from ctypes import c_char, c_int, c_ubyte, c_ushort, c_uint
from ctypes import sizeof, LittleEndianStructure
from time import gmtime, strftime, strptime
from calendar import timegm
from Crypto.Cipher import AES


def eprint(*args, **kwargs):
    """Print to stderr for error/warning messages.
    
    This function works exactly like print() but outputs to stderr instead of stdout.
    Used throughout the codebase for error messages and warnings that should be
    separated from normal program output.
    
    Args:
        *args: Positional arguments passed to print()
        **kwargs: Keyword arguments passed to print()
    """
    print(*args, file=sys.stderr, **kwargs)


class DjiModuleTarget():
    """Stores identification information for a firmware module target.
    
    DJI firmware packages contain multiple modules, each targeting a specific
    hardware component. This class maps the numeric target identifiers to 
    human-readable names and descriptions.
    
    The target byte in FwPkgEntry is encoded as:
        - Bits 0-4 (5 bits): "kind" - identifies the type of hardware (camera, FC, etc.)
        - Bits 5-7 (3 bits): "model" - variant within that hardware type
    
    Attributes:
        kind (int): Hardware type identifier (0-31). Examples:
            1 = Camera, 3 = Main Controller (FLYC), 4 = Gimbal, 8 = Video Encoder
        model (int): Hardware variant (-1 means any/default model). Examples:
            For kind=1 (Camera): 0 = FC300X (Ambarella A9SE), 1 = Camera Loader
        name (str): Short code name used in filenames (e.g., "FC300X", "MCAPP")
        desc (str): Human-readable description of the target
    
    Example:
        >>> target = DjiModuleTarget(1, 0, "FC300X", "camera 'Ambarella A9SE' App")
        >>> print(target.desc)
        "camera 'Ambarella A9SE' App"
    """
    def __init__(self, kind, model, name, desc):
        self.kind = kind
        self.model = model
        self.name = name
        self.desc = desc


# List of known DJI module targets with their identifiers and descriptions.
# Each entry maps a (kind, model) pair to a human-readable name and description.
# When model=-1, it serves as a fallback for unknown model numbers of that kind.
# The target byte in firmware entries encodes: kind (bits 0-4) + model (bits 5-7)
dji_targets = [
    # Camera modules (kind=1) - Ambarella-based camera systems
    DjiModuleTarget( 1,-1, "CAM",     "camera"),                           # Generic camera fallback
    DjiModuleTarget( 1, 0, "FC300X",  "camera 'Ambarella A9SE' App"),      # P3X main camera application
    DjiModuleTarget( 1, 1, "CAMLDR",  "camera 'Ambarella A9SE' Ldr"),      # P3X camera bootloader
    DjiModuleTarget( 1, 2, "CAMBST",  "camera BST"),                       # Camera BST module
    DjiModuleTarget( 1, 4, "CAMBCPU", "camera BCPU"),                      # Camera BCPU coprocessor
    DjiModuleTarget( 1, 5, "CAMLCPU", "camera LCPU"),                      # Camera LCPU coprocessor
    DjiModuleTarget( 1, 6, "ZQ7020",  "camera 'Xilinx Zynq 7020'"),        # FPGA-based camera (Inspire 2)
    # Mobile App (kind=2)
    DjiModuleTarget( 2,-1, "MBAPP",   "mobile app"),                        # DJI GO mobile application
    # Main Controller / Flight Controller (kind=3) - The "brain" of the drone
    DjiModuleTarget( 3,-1, "MC",      "main controller"),                   # Generic FLYC fallback
    DjiModuleTarget( 3, 5, "MCLDR",   "main controller 'A3' ldr"),          # P3X FC bootloader
    DjiModuleTarget( 3, 6, "MCAPP",   "main controller 'A3' app"),          # P3X FC main application
    # Gimbal (kind=4) - Camera stabilization system
    DjiModuleTarget( 4,-1, "GIMBAL",  "gimbal"),                            # Generic gimbal fallback
    DjiModuleTarget( 4, 0, "GIMBAL0", "gimbal mdl 0"),                       # P3X gimbal controller
    # Central Board (kind=5)
    DjiModuleTarget( 5,-1, "CENTER",  "central board"),
    DjiModuleTarget( 5, 0, "CENTER0", "central board mdl 0"),
    # Remote Radio / RC (kind=6)
    DjiModuleTarget( 6,-1, "RMRAD",   "remote radio"),                       # Remote controller radio
    # Wi-Fi (kind=7)
    DjiModuleTarget( 7,-1, "WIFI",    "Wi-Fi"),
    DjiModuleTarget( 7, 0, "WIFI0",   "Wi-Fi mdl 0"),
    # Video Encoder (kind=8) - DaVinci media processors in air unit
    DjiModuleTarget( 8,-1, "VENC",    "video encoder in air"),
    DjiModuleTarget( 8, 0, "DM368",   "video encoder 'DaVinci Dm368 Linux'"), # P3X video encoder
    DjiModuleTarget( 8, 1, "IG810LB2","video encoder 'IG810 LB2_ENC'"),
    # Lightbridge MCU Air (kind=9) - Microcontroller for video transmission
    DjiModuleTarget( 9,-1, "LBMCA",   "lightbridge MCU in air"),
    DjiModuleTarget( 9, 0, "MCA1765", "lightbridge MCU 'STM32F103'"),        # P3X, OSMO_X5R Lightbridge MCU
    # Battery Firmware (kind=10)
    DjiModuleTarget(10,-1, "BATTFW",  "battery firmware"),                   # Smart battery firmware
    # Battery Manager (kind=11)
    DjiModuleTarget(11,-1, "BATTMGR", "battery controller"),
    DjiModuleTarget(11, 0, "BATTERY", "battery controller 1 app"),           # P3X battery controller
    DjiModuleTarget(11, 1, "BATTERY2","battery controller 2 app"),
    # ESC - Electronic Speed Controllers (kind=12) - Motor control
    DjiModuleTarget(12,-1, "ESC",     "electronic speed control"),
    DjiModuleTarget(12, 0, "ESC0",    "electronic speed control 0"),         # P3X motor 1
    DjiModuleTarget(12, 1, "ESC1",    "electronic speed control 1"),         # P3X motor 2
    DjiModuleTarget(12, 2, "ESC2",    "electronic speed control 2"),         # P3X motor 3
    DjiModuleTarget(12, 3, "ESC3",    "electronic speed control 3"),         # P3X motor 4
    # Video Decoder (kind=13) - DaVinci in ground unit / RC
    DjiModuleTarget(13, 0, "VDEC",    "video decoder"),
    DjiModuleTarget(13, 0, "DM365M0", "video decoder 'DaVinci Dm365 Linux'"),
    DjiModuleTarget(13, 1, "DM365M1", "video decoder 'DaVinci Dm385 Linux'"),
    # Lightbridge MCU Ground (kind=14)
    DjiModuleTarget(14,-1, "LBMCG",   "lightbridge MCU on ground"),
    DjiModuleTarget(14, 0, "MCG1765A","lightbridge MCU 'LPC1765 GROUND LB2'"),
    # USB Controllers (kinds 15-16)
    DjiModuleTarget(15,-1, "TXUSBC",  "transmitter usb controller"),
    DjiModuleTarget(15, 0, "TX68013", "transmitter usb 'IG810 LB2_68013_TX'"), # P3X USB controller
    DjiModuleTarget(16,-1, "RXUSBCG", "receiver usb controller"),
    DjiModuleTarget(16, 0, "RX68013", "receiver usb 'IG810 LB2_68013_RX ground'"), # GL300a
    DjiModuleTarget(16, 1, "RXCY2014","receiver usb 'IG810 LB2_CY2014_RX ground'"), # GL300b+
    # Visual Positioning / Obstacle Avoidance (kind=17)
    DjiModuleTarget(17,-1, "MVOM",    "visual positioning"),
    DjiModuleTarget(17, 0, "MVOMC4",  "visual positioning module 'camera'"),  # P3X VPS camera
    DjiModuleTarget(17, 1, "MVOMS0",  "visual positioning module 'sonar'"),   # P3X VPS sonar
    # FPGA modules (kinds 19-20)
    DjiModuleTarget(19,-1, "FPGAA",   "lightbridge FPGA on air"),
    DjiModuleTarget(19, 0, "FPGAA0",  "lightbridge FPGA on air model 0"),     # P3X
    DjiModuleTarget(20,-1, "FPGAG",   "lightbridge FPGA on ground"),
    DjiModuleTarget(20, 3, "FPGAG3",  "lightbridge FPGA on ground 'LB2'"),
    # IMU - Inertial Measurement Unit (kind=25)
    DjiModuleTarget(25,-1, "IMU",     "inertial measurement unit"),
    DjiModuleTarget(25, 0, "IMUA3M0", "inertial measurement unit pt0"),
    DjiModuleTarget(25, 1, "IMUA3M1", "inertial measurement unit pt1"),
    # RTK - Real Time Kinematic GPS (kind=26)
    DjiModuleTarget(26,-1, "RTK",     "real time kinematic"),
    DjiModuleTarget(26, 6, "RTKAPP",  "real time kinematic App"),
    DjiModuleTarget(26, 7, "RTKLDR",  "real time kinematic Ldr"),
    # Wi-Fi Ground (kind=27)
    DjiModuleTarget(27,-1, "WIFIGND", "Wi-Fi ground"),
    # PMU - Power Management Unit (kind=29)
    DjiModuleTarget(29,-1, "PMU",     "power management unit"),
    DjiModuleTarget(29, 0, "PMUA3LDR","power management unit App"),
    DjiModuleTarget(29, 1, "PMUA3APP","power management unit Ldr"),
    # Test modules (kinds 30-31)
    DjiModuleTarget(30,-1, "TESTA",   "test A"),
    DjiModuleTarget(31,-1, "TESTB",   "test B")
]

# AES-128 encryption key used for Type 1 encrypted modules in xV4 containers.
# This key was discovered through reverse engineering and is the same key used
# across many DJI products. It's NOT a secure key - it was designed for obfuscation
# rather than real security, as the same key is hardcoded in all DJI firmware.
encrypt_aes128_key = bytes([0x96, 0x70, 0x9a, 0xD3, 0x26, 0x67, 0x4A, 0xC3, 0x82, 0xB6, 0x69, 0x27, 0xE6, 0xd8, 0x84, 0x21])

# AES-128 CBC mode initialization vector (IV) - all zeros.
# Using a zero IV is cryptographically weak, but DJI uses this approach.
# The encryption is reset for each 256-byte block, further weakening security.
encrypt_aes128_iv = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])


class FwPkgHeader(LittleEndianStructure):
  """Main header structure for DJI xV4 firmware package files.
  
  This 64-byte structure appears at the very beginning of xV4 firmware files
  and contains metadata about the package including manufacturer info, version
  numbers, and the count of firmware modules contained within.
  
  The structure uses little-endian byte order (as indicated by LittleEndianStructure),
  which is standard for ARM-based systems like those in DJI drones.
  
  Attributes:
      magic (c_uint): Magic number 0x12345678 identifying this as a valid xV4 container.
      magic_ver (c_ushort): Format version indicator. Values:
          0x0000 = Version 201412 (earliest format)
          0x0001 = Version 201502 or 201507 (determined by ver_*_enc values)
          0x0002+ = Version 201608+ (BCD-encoded values like 0x1130)
      hdrend_offs (c_ushort): Offset where headers end and module data begins.
          Calculated as: sizeof(FwPkgHeader) + sizeof(FwPkgEntry) * entry_count + 2
      timestamp (c_uint): Unix timestamp of when the firmware was built.
      manufacturer (c_char * 16): Manufacturer name, e.g., "DJI" (null-terminated).
      model (c_char * 16): Product model identifier, e.g., "P3X", "WM220" (null-terminated).
      entry_count (c_ushort): Number of FwPkgEntry structures following this header.
      ver_latest_enc (c_int): XOR-encoded latest firmware version.
          Decode: version = ver_latest_enc ^ 0x5127A564 ^ timestamp
      ver_rollbk_enc (c_int): XOR-encoded rollback version (minimum allowed version).
      padding (c_ubyte * 10): Reserved/padding bytes, typically zeros.
  
  Version Number Encoding:
      DJI encodes version numbers as a 32-bit value:
      - Bits 24-31: Major version (e.g., 01)
      - Bits 16-23: Minor version (e.g., 08)
      - Bits 0-15: Build/SVN number (e.g., 0080)
      Example: Version 01.08.0080 = 0x01080050
  """
  _pack_ = 1  # No padding between fields - pack tightly
  _fields_ = [('magic', c_uint),             # Offset 0: Magic number 0x12345678
              ('magic_ver', c_ushort),       # Offset 4: Format version
              ('hdrend_offs', c_ushort),     # Offset 6: End of headers offset
              ('timestamp', c_uint),         # Offset 8: Build timestamp (Unix epoch)
              ('manufacturer', c_char * 16), # Offset 12: Manufacturer string
              ('model', c_char * 16),        # Offset 28: Model identifier string
              ('entry_count', c_ushort),     # Offset 44: Number of module entries
              ('ver_latest_enc', c_int),     # Offset 46: Encoded latest version
              ('ver_rollbk_enc', c_int),     # Offset 50: Encoded rollback version
              ('padding', c_ubyte * 10)]     # Offset 54: Reserved (total = 64 bytes)

  def set_ver_latest(self, ver):
    """Set the latest firmware version using XOR encoding.
    
    The version is XOR'd with a magic constant and the timestamp to produce
    the encoded value stored in the header. This simple obfuscation prevents
    casual reading of version numbers but provides no real security.
    
    Args:
        ver (int): Version number encoded as 32-bit value
            (major << 24 | minor << 16 | build)
    """
    self.ver_latest_enc = 0x5127A564 ^ ver ^ self.timestamp

  def set_ver_rollbk(self, ver):
    """Set the rollback (minimum) firmware version using XOR encoding.
    
    The rollback version is the minimum version that can be installed.
    This prevents downgrade attacks where an attacker might try to install
    older firmware with known vulnerabilities.
    
    Args:
        ver (int): Version number encoded as 32-bit value
            (major << 24 | minor << 16 | build)
    """
    self.ver_rollbk_enc = 0x5127A564 ^ ver ^ self.timestamp

  def get_format_version(self):
    """Determine the xV4 format version based on magic values.
    
    DJI has used several versions of the xV4 format over the years.
    This method examines the magic bytes and version fields to determine
    which format version is being used.
    
    Returns:
        int: Format version year-month indicator:
            0 = Invalid/unrecognized format
            201412 = December 2014 format (earliest)
            201502 = February 2015 format (no version encoding)
            201507 = July 2015 format (with version encoding)
            201608 = August 2016+ format (BCD magic_ver)
    """
    if self.magic == 0x12345678 and self.magic_ver == 0x0000:
        # Earliest format - versions are expected to be set properly
        # Surprisingly, values are only invalid for magic_ver == 1
        if (self.ver_latest_enc != 0):
            return 201412
        else:
            return 0
    elif self.magic == 0x12345678 and self.magic_ver == 0x0001:
        # Version 1 format - check if versions are used
        if (self.ver_latest_enc == 0 and self.ver_rollbk_enc == 0):
            return 201502  # Versions not used
        else:
            return 201507  # Versions are XOR-encoded
    # Higher magic_ver - allow any 16-bit value with BCD digits (0-9 only)
    # This validates that each hex digit is valid BCD (0-9, not A-F)
    elif self.magic == 0x12345678 and self.magic_ver >= 0x0002 and self.magic_ver <= 0xFFFF and \
      all(((self.magic_ver >> n) & 0xF <= 9) for n in range(0,16,4)):
        return 201608
    else:
        return 0  # Unrecognized format

  def set_format_version(self, ver):
    """Configure header fields for a specific xV4 format version.
    
    Different format versions have different requirements for how the
    magic, magic_ver, and version encoding fields should be set.
    
    Args:
        ver (int): Format version to configure (201412, 201502, 201507, or 201608)
    
    Raises:
        ValueError: If an unsupported format version is specified
    """
    if ver == 201412:
        self.magic = 0x12345678
        self.magic_ver = 0x0000
        self.set_ver_latest(0)
        self.set_ver_rollbk(0)
    elif ver == 201502:
        # February 2015 format doesn't use version encoding
        self.magic = 0x12345678
        self.magic_ver = 0x0001
        self.ver_latest_enc = 0
        self.ver_rollbk_enc = 0
    elif ver == 201507:
        self.magic = 0x12345678
        self.magic_ver = 0x0001
        self.set_ver_latest(0)
        self.set_ver_rollbk(0)
    elif ver == 201608:
        self.magic = 0x12345678
        # Use 0x1130 as default magic_ver - most common value seen in the wild
        # This will typically be overwritten with the actual value from INI
        self.magic_ver = 0x1130
        self.set_ver_latest(0)
        self.set_ver_rollbk(0)
    else:
        raise ValueError("Unsupported package format version.")

  def dict_export(self):
    """Export header fields to a dictionary for display or serialization.
    
    Converts the binary structure to a Python dictionary with decoded
    version numbers and hex-formatted padding bytes.
    
    Returns:
        dict: Dictionary containing all header fields with decoded values
    """
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    # Decode the XOR-encoded version numbers
    varkey = 'ver_latest'
    d[varkey] = d['timestamp'] ^ d[varkey+"_enc"] ^ 0x5127A564
    varkey = 'ver_rollbk'
    d[varkey] = d['timestamp'] ^ d[varkey+"_enc"] ^ 0x5127A564
    # Format padding as hex string for readability
    varkey = 'padding'
    d[varkey] = "".join("{:02X}".format(x) for x in d[varkey])
    return d

  def ini_export(self, fp):
    """Export header fields to an INI-style configuration file.
    
    Writes the header information in a human-readable format that can
    be edited and used to recreate the firmware package.
    
    Args:
        fp: File-like object to write INI content to
    """
    d = self.dict_export()
    fp.write("# DJI Firmware Container main header file.\n")
    fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
    # Write format version for re-creation
    varkey = 'pkg_format'
    fp.write("{:s}={:d}\n".format(varkey,self.get_format_version()))
    # Only write magic_ver for newer formats where it varies
    if self.magic_ver >= 2:
        varkey = 'magic_ver'
        fp.write("{:s}={:04x}\n".format(varkey,self.magic_ver))
    varkey = 'manufacturer'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey].decode("utf-8")))
    varkey = 'model'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey].decode("utf-8")))
    varkey = 'timestamp'
    fp.write("{:s}={:s}\n".format(varkey,strftime("%Y-%m-%d %H:%M:%S",gmtime(d[varkey]))))
    # Format version as MM.mm.BBBB (major.minor.build)
    varkey = 'ver_latest'
    fp.write("{:s}={:02d}.{:02d}.{:04d}\n".format(varkey, (d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535))
    varkey = 'ver_rollbk'
    fp.write("{:s}={:02d}.{:02d}.{:04d}\n".format(varkey, (d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535))
    # Padding is not written - it's just zeros

  def __repr__(self):
    """Return a pretty-printed string representation of the header."""
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)

class FwPkgEntry(LittleEndianStructure):
  """Firmware module entry structure within xV4 packages.
  
  Each firmware module in an xV4 package has a 52-byte entry in the header
  that describes the module's target hardware, version, location, size, and
  checksums. The entries appear sequentially after the main FwPkgHeader.
  
  The target byte encodes both the hardware type ("kind") and variant ("model"):
      - Bits 0-4: kind (hardware type, 0-31)
      - Bits 5-7: model (variant within type, 0-7)
  
  Attributes:
      target (c_ubyte): Target hardware identifier (kind + model encoded).
      spcoding (c_ubyte): Special coding byte containing:
          - Bits 0-3: SPL value (special value, purpose unclear)
          - Bits 4-7: Encryption type (0=none, 1=AES-128)
      reserved2 (c_ushort): Reserved field, should be 0.
      version (c_uint): Module version number (major.minor.build encoded).
      dt_offs (c_uint): Offset from start of file to module data.
      stored_len (c_uint): Length of module data as stored (may be encrypted).
      decrypted_len (c_uint): Length of module data after decryption.
      stored_md5 (c_ubyte * 16): MD5 checksum of stored (encrypted) data.
      decrypted_md5 (c_ubyte * 16): MD5 checksum of decrypted data.
  
  Note:
      The preencrypted attribute (not in _fields_) is set at runtime to track
      whether a module was extracted in encrypted form due to missing crypto.
  """
  _pack_ = 1  # No padding between fields
  _fields_ = [('target', c_ubyte),           # Offset 0: Target hardware (kind|model)
              ('spcoding', c_ubyte),         # Offset 1: Encryption type | SPL value
              ('reserved2', c_ushort),       # Offset 2: Reserved
              ('version', c_uint),           # Offset 4: Module version
              ('dt_offs', c_uint),           # Offset 8: Data offset in file
              ('stored_len', c_uint),        # Offset 12: Stored data length
              ('decrypted_len', c_uint),     # Offset 16: Decrypted data length
              ('stored_md5', c_ubyte * 16),  # Offset 20: MD5 of stored data
              ('decrypted_md5', c_ubyte * 16)] # Offset 36: MD5 of decrypted data
                                             # Total: 52 bytes
  preencrypted = 0  # Runtime flag: 1 if extracted without decryption

  def get_encrypt_type(self):
      """Get the encryption type from the spcoding byte.
      
      Returns:
          int: Encryption type (0=none, 1=AES-128, other values unknown)
      """
      return (self.spcoding >> 4) & 0x0F

  def set_encrypt_type(self, enctype):
      """Set the encryption type in the spcoding byte.
      
      Args:
          enctype (int): Encryption type (0=none, 1=AES-128)
      """
      self.spcoding = (self.spcoding & 0x0F) | ((enctype & 0x0F) << 4)

  def get_splvalue(self):
      """Get the SPL value from the spcoding byte.
      
      The purpose of the SPL value is not fully understood, but it may
      relate to security patch level or special processing flags.
      
      Returns:
          int: SPL value (0-15)
      """
      return (self.spcoding) & 0x0F

  def set_splvalue(self, splval):
      """Set the SPL value in the spcoding byte.
      
      Args:
          splval (int): SPL value (0-15)
      """
      self.spcoding = (self.spcoding & 0xF0) | (splval & 0x0F)

  def target_name(self):
    """Get human-readable name for the target hardware.
    
    Looks up the target identifier in the dji_targets list and returns
    a descriptive name. Falls back to generic descriptions if the
    specific model is not found.
    
    Returns:
        str: Human-readable target description
    """
    # Extract kind (hardware type) and model (variant) from target byte
    tg_kind = getattr(self, 'target') & 31      # Bits 0-4
    tg_model = (getattr(self, 'target') >> 5) & 7  # Bits 5-7
    # Try to find exact match (kind + model)
    module_info = next((mi for mi in dji_targets if mi.kind == tg_kind and mi.model == tg_model), None)
    if (module_info is not None):
        return module_info.desc
    # If not found, try getting generic description for this kind (model=-1)
    module_info = next((mi for mi in dji_targets if mi.kind == tg_kind and mi.model == -1), None)
    if (module_info is not None):
        return "{:s} model {:02d}".format(module_info.desc,tg_model)
    # If category also not found, return as unknown device
    return "device kind {:02} model {:02}".format(tg_kind,tg_model)

  def hex_stored_md5(self):
    """Return the stored data MD5 checksum as a hexadecimal string.
    
    Returns:
        str: 32-character lowercase hex string representing the MD5
    """
    varkey = 'stored_md5'
    return "".join("{:02x}".format(x) for x in getattr(self, varkey))

  def hex_decrypted_md5(self):
    """Return the decrypted data MD5 checksum as a hexadecimal string.
    
    Returns:
        str: 32-character lowercase hex string representing the MD5
    """
    varkey = 'decrypted_md5'
    return "".join("{:02x}".format(x) for x in getattr(self, varkey))

  def dict_export(self):
    """Export entry fields to a dictionary for display or serialization.
    
    Converts version to human-readable format and checksums to hex strings.
    
    Returns:
        dict: Dictionary with all entry fields in readable format
    """
    d = dict()
    for (varkey, vartype) in self._fields_:
        d[varkey] = getattr(self, varkey)
    # Format version as MM.mm.BBBB
    varkey = 'version'
    d[varkey] = "{:02d}.{:02d}.{:04d}".format((d[varkey]>>24)&255, (d[varkey]>>16)&255, (d[varkey])&65535)
    # Format checksums as hex strings
    varkey = 'stored_md5'
    d[varkey] = "".join("{:02x}".format(x) for x in d[varkey])
    varkey = 'decrypted_md5'
    d[varkey] = "".join("{:02x}".format(x) for x in d[varkey])
    # Format target as mKKMM string (kind, model)
    varkey = 'target'
    d[varkey] = "m{:02d}{:02d}".format(d[varkey]&31, (d[varkey]>>5)&7)
    # Add derived fields
    varkey = 'encrypt_type'
    d[varkey] = self.get_encrypt_type()
    varkey = 'splvalue'
    d[varkey] = self.get_splvalue()
    varkey = 'target_name'
    d[varkey] = self.target_name()
    return d

  def ini_export(self, fp):
    """Export entry fields to an INI-style configuration file.
    
    Args:
        fp: File-like object to write INI content to
    """
    d = self.dict_export()
    fp.write("# DJI Firmware Container module header file.\n")
    fp.write("# Stores firmware for {:s}\n".format(d['target_name']))
    fp.write(strftime("# Generated on %Y-%m-%d %H:%M:%S\n", gmtime()))
    varkey = 'target'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'version'
    fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'encrypt_type'
    fp.write("{:s}={:d}\n".format(varkey,d[varkey]))
    if (d[varkey] != 0):
        # If encryption is used, record whether we extracted encrypted
        varkey = 'preencrypted'
        fp.write("{:s}={:d}\n".format(varkey,self.preencrypted))
    if (self.preencrypted):
        # Store decrypted MD5 since we can't compute it for pre-encrypted files
        varkey = 'decrypted_md5'
        fp.write("{:s}={:s}\n".format(varkey,d[varkey]))
    varkey = 'splvalue'
    fp.write("{:s}={:d}\n".format(varkey,d[varkey]))
    varkey = 'reserved2'
    fp.write("{:s}={:04X}\n".format(varkey,d[varkey]))

  def __repr__(self):
    """Return a pretty-printed string representation of the entry."""
    d = self.dict_export()
    from pprint import pformat
    return pformat(d, indent=4, width=1)


# CRC-16 lookup table for header checksum calculation.
# This is a non-standard CRC-16 variant (appears to be CRC-16-CCITT reflected/reversed).
# The table contains pre-computed CRC values for each possible byte value (0x00-0xFF),
# allowing efficient checksum calculation through table lookups instead of bit manipulation.
# Initial seed value for xV4 header checksums is 0x3692.
crc16_tab = [
  0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
  0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
  0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
  0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
  0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
  0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
  0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
  0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
  0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
  0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
  0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
  0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
  0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
  0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
  0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
  0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
  0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
  0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
  0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
  0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
  0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
  0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
  0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
  0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
  0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
  0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
  0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
  0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
  0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
  0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
  0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
  0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78,
]

def dji_calculate_crc16_part(buf, pcrc):
    """Calculate a non-standard CRC-16 checksum for DJI firmware headers.
    
    This is a table-driven CRC-16 implementation that appears to be a variant
    of CRC-16-CCITT (reflected). DJI uses this checksum to verify the integrity
    of the package header and all module entry headers.
    
    The algorithm processes each byte by:
    1. XORing the byte with the low 8 bits of the current CRC
    2. Looking up the result in the pre-computed table
    3. XORing with the CRC shifted right by 8 bits
    
    Note: This is similar to Ambarella's CRC but limited to 16 bits.
    
    Args:
        buf (bytes): Data buffer to checksum
        pcrc (int): Previous CRC value (initial seed for xV4 headers is 0x3692)
    
    Returns:
        int: 16-bit CRC value
    
    Example:
        >>> crc = dji_calculate_crc16_part(header_bytes, 0x3692)
        >>> crc = dji_calculate_crc16_part(entry_bytes, crc)  # Continue with same CRC
    """
    crc = pcrc
    for octet in buf:
        # XOR current byte with low byte of CRC, look up in table, 
        # XOR with CRC shifted right 8 bits
        crc = crc16_tab[(crc ^ octet) & 0xff] ^ (crc >> 8)
    return crc & 0xffff  # Mask to 16 bits


def dji_decrypt_block(cipher_buf, enc_key, enc_iv):
    """Decrypt a buffer using DJI's AES-128-CBC implementation.
    
    DJI uses a non-standard approach to AES encryption: instead of encrypting
    the entire buffer with a single cipher stream, they reinitialize the cipher
    for every 256-byte block. This "block-by-block" approach is cryptographically
    weaker than standard CBC mode because each block's encryption is independent.
    
    Why DJI does this is unclear - it may be a mistake, or it may be intentional
    to allow partial decryption or simplify implementation on embedded systems.
    
    Args:
        cipher_buf (bytes): Encrypted data to decrypt
        enc_key (bytes): 16-byte AES-128 encryption key
        enc_iv (bytes): 16-byte initialization vector (typically all zeros for DJI)
    
    Returns:
        tuple: (decrypted_data, iv) - The decrypted bytes and the IV
        
    Note:
        The returned IV is unchanged since DJI reinits for each block.
    """
    block_sz = 256  # DJI uses 256-byte blocks, not the standard 16-byte AES block
    plain_buf = b""
    for cbpos in range(0, len(cipher_buf), block_sz):
        # Reinitialize the cipher for each 256-byte block - this is DJI's approach
        crypto = AES.new(enc_key, AES.MODE_CBC, enc_iv)
        plain_buf += crypto.decrypt(cipher_buf[cbpos:cbpos+block_sz])
    return plain_buf, enc_iv


def dji_encrypt_block(cipher_buf, enc_key, enc_iv):
    """Encrypt a buffer using DJI's AES-128-CBC implementation.
    
    This is the inverse of dji_decrypt_block(). Like decryption, encryption
    reinitializes the AES cipher for every 256-byte block, matching DJI's
    non-standard approach.
    
    Args:
        cipher_buf (bytes): Plaintext data to encrypt
        enc_key (bytes): 16-byte AES-128 encryption key
        enc_iv (bytes): 16-byte initialization vector (typically all zeros for DJI)
    
    Returns:
        tuple: (encrypted_data, iv) - The encrypted bytes and the IV
    """
    block_sz = 256  # DJI uses 256-byte blocks
    plain_buf = b""
    for cbpos in range(0, len(cipher_buf), block_sz):
        # Reinitialize the cipher for each block - matching DJI's approach
        crypto = AES.new(enc_key, AES.MODE_CBC, enc_iv)
        plain_buf += crypto.encrypt(cipher_buf[cbpos:cbpos+block_sz])
    return plain_buf, enc_iv


def dji_write_fwpkg_head(po, pkghead, minames):
    fname = "{:s}_head.ini".format(po.mdprefix)
    fwheadfile = open(fname, "w")
    pkghead.ini_export(fwheadfile)
    fwheadfile.write("{:s}={:s}\n".format("modules",' '.join(minames)))
    fwheadfile.close()


def dji_read_fwpkg_head(po):
    pkghead = FwPkgHeader()
    fname = "{:s}_head.ini".format(po.mdprefix)
    parser = configparser.ConfigParser()
    with open(fname, "r") as lines:
        lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
        parser.read_file(lines)
    # Set magic fields properly
    pkgformat = parser.get("asection", "pkg_format").encode("utf-8")
    pkghead.set_format_version(int(pkgformat))
    if parser.has_option('asection', 'magic_ver'):
        magicver_s = parser.get('asection', 'magic_ver')
        pkghead.magic_ver = int(magicver_s,16)
    # Set the rest of the fields
    pkghead.manufacturer = parser.get("asection", "manufacturer").encode("utf-8")
    pkghead.model = parser.get("asection", "model").encode("utf-8")
    pkghead.timestamp = timegm(strptime(parser.get("asection", "timestamp"),"%Y-%m-%d %H:%M:%S"))
    ver_latest_s = parser.get("asection", "ver_latest")
    ver_latest_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[.](?P<svn>[0-9A-Fa-f]+)', ver_latest_s)
    pkghead.set_ver_latest(
       ((int(ver_latest_m.group("major"), 10) & 0xff) << 24) +
       ((int(ver_latest_m.group("minor"), 10) & 0xff) << 16) +
       (int(ver_latest_m.group("svn"), 10) & 0xffff)
    )
    ver_rollbk_s = parser.get("asection", "ver_rollbk")
    ver_rollbk_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[.](?P<svn>[0-9A-Fa-f]+)', ver_rollbk_s)
    pkghead.set_ver_rollbk(
      ((int(ver_rollbk_m.group("major"), 10) & 0xff) << 24) +
      ((int(ver_rollbk_m.group("minor"), 10) & 0xff) << 16) +
      (int(ver_rollbk_m.group("svn"), 10) & 0xffff)
    )
    minames_s = parser.get("asection", "modules")
    minames = minames_s.split(' ')
    pkghead.entry_count = len(minames)
    pkghead.hdrend_offs = sizeof(pkghead) + sizeof(FwPkgEntry)*pkghead.entry_count + sizeof(c_ushort)
    del parser
    return (pkghead, minames)


def dji_write_fwentry_head(po, i, e, miname):
    fname = "{:s}_{:s}.ini".format(po.mdprefix,miname)
    fwheadfile = open(fname, "w")
    e.ini_export(fwheadfile)
    fwheadfile.close()


def dji_read_fwentry_head(po, i, miname):
    hde = FwPkgEntry()
    fname = "{:s}_{:s}.ini".format(po.mdprefix,miname)
    parser = configparser.ConfigParser()
    with open(fname, "r") as lines:
        lines = itertools.chain(("[asection]",), lines)  # This line adds section header to ini
        parser.read_file(lines)
    target_s = parser.get("asection", "target")
    target_m = re.search('m(?P<kind>[0-9]{2})(?P<model>[0-9]{2})', target_s)
    hde.target = ((int(target_m.group("kind"),10)&0x1f)) + ((int(target_m.group("model"),10)&0x07)<<5)
    version_s = parser.get("asection", "version")
    version_m = re.search('(?P<major>[0-9]+)[.](?P<minor>[0-9]+)[.](?P<svn>[0-9]+)', version_s)
    hde.version = (
      ((int(version_m.group("major"), 10) & 0xff) << 24) +
      ((int(version_m.group("minor"), 10) % 0xff) << 16) +
      (int(version_m.group("svn"), 10) % 0xffff)
    )
    if parser.has_option("asection", "preencrypted"):
        hde.preencrypted = int(parser.get("asection", "preencrypted"),10)
    if (hde.preencrypted):
        decrypted_md5_s = parser.get("asection", "decrypted_md5")
        hde.decrypted_md5 = (c_ubyte * 16).from_buffer_copy(binascii.unhexlify(decrypted_md5_s))
    hde.set_encrypt_type( int(parser.get("asection", "encrypt_type"),10) )
    hde.set_splvalue( int(parser.get("asection", "splvalue"),10) )
    hde.reserved2 = int(parser.get("asection", "reserved2"),16)
    del parser
    return (hde)

def dji_extract(po, fwpkgfile):
    pkghead = FwPkgHeader()
    if fwpkgfile.readinto(pkghead) != sizeof(pkghead):
        raise EOFError("Could not read firmware package file header.")
    pkgformat = pkghead.get_format_version()
    if pkgformat == 0:
        if (not po.force_continue):
            eprint("{}: Error: Unexpected magic value in main header; input file is not a firmware package.".format(po.fwpkg))
            exit(1)
        eprint("{}: Warning: Unexpected magic value in main header; will try to extract anyway.".format(po.fwpkg))
    if (po.verbose > 1):
        print("{}: Package format version {:d} detected".format(po.fwpkg,pkgformat))
    if (pkghead.ver_latest_enc == 0 and pkghead.ver_rollbk_enc == 0):
        eprint("{}: Warning: Unversioned firmware package identified; this format is not fully supported.".format(po.fwpkg))
        # In this format, versions should be set from file name, and CRC16 of the header should be equal to values hard-coded in updater
    if (po.verbose > 1):
        print("{}: Header:".format(po.fwpkg))
        print(pkghead)
    curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead), 0x3692)

    pkgmodules = []
    for i in range(pkghead.entry_count):
        hde = FwPkgEntry()
        if fwpkgfile.readinto(hde) != sizeof(hde):
            raise EOFError("Couldn't read firmware package file entry.")
        if (po.verbose > 1):
            print("{}: Module index {:d}".format(po.fwpkg,i))
            print(hde)
        curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(hde)).from_buffer_copy(hde), curhead_checksum)
        if hde.stored_len != hde.decrypted_len:
            eprint("{}: Warning: decrypted size differs from stored one, {:d} instead of {:d}; this is not supported."
              .format(po.fwpkg,hde.decrypted_len,hde.stored_len))
        chksum_enctype = hde.get_encrypt_type()
        if (chksum_enctype != 0):
            if (po.no_crypto):
                hde.preencrypted = 1
            elif (chksum_enctype == 1):
                encrypt_key = encrypt_aes128_key
                encrypt_iv  = encrypt_aes128_iv
            else:
                # Since we cannot decode the encryption, mark the entry as pre-encrypted to extract in encrypted form
                eprint("{}: Warning: Unknown encryption {:d} in module {:d}, extracting encrypted."
                  .format(po.fwpkg,chksum_enctype,i))
                hde.preencrypted = 1
        pkgmodules.append(hde)

    pkghead_checksum = c_ushort()
    if fwpkgfile.readinto(pkghead_checksum) != sizeof(pkghead_checksum):
        raise EOFError("Couldn't read firmware package file header checksum.")

    if curhead_checksum != pkghead_checksum.value:
        eprint("{}: Warning: Firmware package file header checksum did not match; should be {:04X}, found {:04X}."
          .format(po.fwpkg, pkghead_checksum.value, curhead_checksum))
    elif (po.verbose > 1):
        print("{}: Headers checksum {:04X} matches.".format(po.fwpkg,pkghead_checksum.value))

    if fwpkgfile.tell() != pkghead.hdrend_offs:
        eprint("{}: Warning: Header end offset does not match; should end at {}, ends at {}."
          .format(po.fwpkg,pkghead.hdrend_offs,fwpkgfile.tell()))

    # Prepare array of names; "0" will mean empty index
    minames = ["0"]*len(pkgmodules)
    # Name the modules after target component
    for i, hde in enumerate(pkgmodules):
        if hde.stored_len > 0:
            d = hde.dict_export()
            minames[i] = "{:s}".format(d['target'])
    # Rename targets in case of duplicates
    minames_seen = set()
    for i in range(len(minames)):
        miname = minames[i]
        if miname in minames_seen:
            # Add suffix a..z to multiple uses of the same module
            for miname_suffix in range(97,110):
                if miname+chr(miname_suffix) not in minames_seen:
                    break
            # Show warning the first time duplicate is found
            if (miname_suffix == 97):
                eprint("{}: Warning: Found multiple modules {:s}; invalid firmware.".format(po.fwpkg,miname))
            minames[i] = miname+chr(miname_suffix)
        minames_seen.add(minames[i])
    minames_seen = None

    dji_write_fwpkg_head(po, pkghead, minames)

    for i, hde in enumerate(pkgmodules):
        if minames[i] == "0":
            if (po.verbose > 0):
                print("{}: Skipping module index {}, {} bytes".format(po.fwpkg,i,hde.stored_len))
            continue
        if (po.verbose > 0):
            print("{}: Extracting module index {}, {} bytes".format(po.fwpkg,i,hde.stored_len))
        chksum_enctype = hde.get_encrypt_type()
        stored_chksum = hashlib.md5()
        decrypted_chksum = hashlib.md5()
        dji_write_fwentry_head(po, i, hde, minames[i])
        fwitmfile = open("{:s}_{:s}.bin".format(po.mdprefix,minames[i]), "wb")
        fwpkgfile.seek(hde.dt_offs)
        stored_n = 0
        decrypted_n = 0
        while stored_n < hde.stored_len:
            # read block limit must be a multiplication of encryption block size
            copy_buffer = fwpkgfile.read(min(1024 * 1024, hde.stored_len - stored_n))
            if not copy_buffer:
                break
            stored_n += len(copy_buffer)
            stored_chksum.update(copy_buffer)
            if (chksum_enctype != 0) and (not hde.preencrypted):
                copy_buffer, encrypt_iv = dji_decrypt_block(copy_buffer, encrypt_key, encrypt_iv)
            fwitmfile.write(copy_buffer)
            decrypted_n += len(copy_buffer)
            decrypted_chksum.update(copy_buffer)
        fwitmfile.close()
        if (stored_chksum.hexdigest() != hde.hex_stored_md5()):
            eprint("{}: Warning: Module index {:d} stored checksum mismatch; got {:s}, expected {:s}."
              .format(po.fwpkg,i,stored_chksum.hexdigest(),hde.hex_stored_md5()))
        if (not hde.preencrypted) and (decrypted_chksum.hexdigest() != hde.hex_decrypted_md5()):
            eprint("{}: Warning: Module index {:d} decrypted checksum mismatch; got {:s}, expected {:s}."
              .format(po.fwpkg,i,decrypted_chksum.hexdigest(),hde.hex_decrypted_md5()))
            eprint("{}: Module index {:d} may be damaged due to bad decryption; use no-crypto option to leave it as-is."
              .format(po.fwpkg,i))
        if (not hde.preencrypted) and (decrypted_n != hde.decrypted_len):
            eprint("{}: Warning: decrypted size mismatch, {:d} instead of {:d}."
              .format(po.fwpkg,decrypted_n,hde.decrypted_len))
        if (po.verbose > 1):
            print("{}: Module index {:d} stored checksum {:s}".format(po.fwpkg,i,stored_chksum.hexdigest()))
    return


def dji_create(po, fwpkgfile):
    # Read headers from INI files
    (pkghead, minames) = dji_read_fwpkg_head(po)
    pkgmodules = []
    # Create module entry for each partition
    for i, miname in enumerate(minames):
        if miname == "0":
            hde = FwPkgEntry()
        else:
            hde = dji_read_fwentry_head(po, i, miname)
        pkgmodules.append(hde)
    # Write the unfinished headers
    if (po.verbose > 2):
        print("{}: File map: 0x{:08x} FwPkgHeader".format(po.fwpkg,fwpkgfile.tell()))
    fwpkgfile.write((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead))
    for hde in pkgmodules:
        if (po.verbose > 2):
            print("{}: File map: 0x{:08x} FwPkgEntry[m{:02d}{:02d}]".format(po.fwpkg,
              fwpkgfile.tell(), getattr(hde, 'target') & 31, (getattr(hde, 'target') >> 5) & 7))
        fwpkgfile.write((c_ubyte * sizeof(hde)).from_buffer_copy(hde))
    fwpkgfile.write((c_ubyte * sizeof(c_ushort))())
    # Write module data
    for i, miname in enumerate(minames):
        hde = pkgmodules[i]
        if miname == "0":
            if (po.verbose > 0):
                print("{}: Empty module index {:d}".format(po.fwpkg,i))
            continue
        if (po.verbose > 0):
            print("{}: Copying module index {:d}".format(po.fwpkg,i))
        fname = "{:s}_{:s}.bin".format(po.mdprefix,miname)
        # Skip unused pkgmodules
        if (os.stat(fname).st_size < 1):
            eprint("{}: Warning: module index {:d} empty".format(po.fwpkg,i))
            continue
        chksum_enctype = hde.get_encrypt_type()
        epos = fwpkgfile.tell()
        # Check for data encryption
        if (chksum_enctype != 0) and (not hde.preencrypted):
            if (po.no_crypto):
                if (not po.force_continue):
                    eprint("{}: Error: Module {:d} needs encryption {:d}, but crypto is disabled."
                      .format(po.fwpkg,chksum_enctype,i))
                    exit(1)
                eprint("{}: Warning: Module {:d} needs encryption {:d}, but crypto is disabled; switching to unencrypted."
                  .format(po.fwpkg,chksum_enctype,i))
                hde.set_encrypt_type(0)
                chksum_enctype = hde.get_encrypt_type()
            elif (chksum_enctype == 1):
                encrypt_key = encrypt_aes128_key
                encrypt_iv  = encrypt_aes128_iv
            else:
                if (not po.force_continue):
                    eprint("{}: Error: Unknown encryption {:d} in module {:d}; cannot encrypt.".format(po.fwpkg,chksum_enctype,i))
                    exit(1)
                eprint("{}: Warning: Unknown encryption {:d} in module {:d}; switching to unencrypted.".format(po.fwpkg,chksum_enctype,i))
                hde.set_encrypt_type(0)
                chksum_enctype = hde.get_encrypt_type()
        # Copy partition data and compute checksum
        if (po.verbose > 2):
            print("{}: File map: 0x{:08x} FwModuleData[m{:02d}{:02d}]".format(po.fwpkg,
              epos, getattr(hde, 'target') & 31, (getattr(hde, 'target') >> 5) & 7))
        fwitmfile = open(fname, "rb")
        stored_chksum = hashlib.md5()
        decrypted_chksum = hashlib.md5()
        decrypted_n = 0
        while True:
            # read block limit must be a multiplication of encryption block size
            copy_buffer = fwitmfile.read(1024 * 1024)
            if not copy_buffer:
                break
            decrypted_chksum.update(copy_buffer)
            decrypted_n += len(copy_buffer)
            if (chksum_enctype != 0) and (not hde.preencrypted):
                copy_buffer, encrypt_iv = dji_encrypt_block(copy_buffer, encrypt_key, encrypt_iv)
            stored_chksum.update(copy_buffer)
            fwpkgfile.write(copy_buffer)
        fwitmfile.close()
        hde.dt_offs = epos
        hde.stored_len = fwpkgfile.tell() - epos
        # We do not support pre-encryption which changes length of data
        # If we need it at some point, the only way is to store decrypted_len in INI file
        hde.decrypted_len = decrypted_n
        hde.stored_md5 = (c_ubyte * 16).from_buffer_copy(stored_chksum.digest())
        if (hde.preencrypted):
            # If the file is pre-encrypted, then it has to have encryption type and MD5 set from INI file
            if (chksum_enctype == 0):
                eprint("{}: Warning: Module {:d} marked as pre-encrypted, but with no encryption type.".format(po.fwpkg,i))
            if all([ v == 0 for v in hde.decrypted_md5 ]):
                eprint("{}: Warning: Module {:d} marked as pre-encrypted, but decrypted MD5 is zeros.".format(po.fwpkg,i))
            else:
                print("{}: Module {:d} marked as pre-encrypted; decrypted MD5 accepted w/o verification.".format(po.fwpkg,i))
        else:
            # If the file is not pre-encrypted, then we should just use the MD5 we've computed
            hde.decrypted_md5 = (c_ubyte * 16).from_buffer_copy(decrypted_chksum.digest())
        pkgmodules[i] = hde
    if (po.verbose > 2):
        print("{}: File map: 0x{:08x} FwDataEnd".format(po.fwpkg, fwpkgfile.tell()))
    # Write all headers again
    fwpkgfile.seek(0,os.SEEK_SET)
    fwpkgfile.write((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead))
    curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(pkghead)).from_buffer_copy(pkghead), 0x3692)
    for hde in pkgmodules:
        fwpkgfile.write((c_ubyte * sizeof(hde)).from_buffer_copy(hde))
        curhead_checksum = dji_calculate_crc16_part((c_ubyte * sizeof(hde)).from_buffer_copy(hde), curhead_checksum)
    pkghead_checksum = c_ushort(curhead_checksum)
    fwpkgfile.write((c_ubyte * sizeof(c_ushort)).from_buffer_copy(pkghead_checksum))


def main():
    """ Main executable function.

    Its task is to parse command line options and call a function which performs requested command.
    """
    parser = argparse.ArgumentParser(description=__doc__.split('.')[0])

    parser.add_argument('-p', '--fwpkg', default="", type=str, required=True,
          help="name of the firmware package file")

    parser.add_argument('-m', '--mdprefix', default="", type=str,
          help=("directory and file name prefix for the single decomposed firmware modules "
           "(default is base name of fwpkg with extension stripped, in working dir)"))

    parser.add_argument('-f', '--force-continue', action='store_true',
          help="force continuing execution despite warning signs of issues")

    parser.add_argument('-c', '--no-crypto', action='store_true',
          help="disable cryptography - do not encrypt/decrypt modules")

    parser.add_argument('-v', '--verbose', action='count', default=0,
          help="increases verbosity level; max level is set by -vvv")

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-x', '--extract', action='store_true',
          help="extract firmware package into modules")

    subparser.add_argument('-a', '--add', action='store_true',
          help="add module files to firmware package")

    subparser.add_argument('--version', action='version', version="%(prog)s {version} by {author}"
            .format(version=__version__, author=__author__),
          help="display version information and exit")

    po = parser.parse_args()

    if len(po.fwpkg) > 0 and len(po.mdprefix) == 0:
        po.mdprefix = os.path.splitext(os.path.basename(po.fwpkg))[0]

    if po.extract:
        if (po.verbose > 0):
            print("{}: Opening for extraction".format(po.fwpkg))
        with open(po.fwpkg, 'rb') as fwpkgfile:
            dji_extract(po, fwpkgfile)

    elif po.add:
        if (po.verbose > 0):
            print("{}: Opening for creation".format(po.fwpkg))
        with open(po.fwpkg, 'wb') as fwpkgfile:
            dji_create(po, fwpkgfile)

    else:
        raise NotImplementedError("Unsupported command.")


if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        if 0: raise
        sys.exit(10)
