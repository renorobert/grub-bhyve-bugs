# JPEG bugs

## hs_vs_payload.jpg

```
==19110==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61d00001f388 at pc 0x00000042510d bp 0x7fffcdb221f0 sp 0x7fffcdb221e0
WRITE of size 8 at 0x61d00001f388 thread T0
    #0 0x42510c in grub_memset /home/renorobert/grub-2.00/grub-core/kern/misc.c:497
    #1 0x440780 in grub_jpeg_decode_du ../video/readers/jpeg.c:488
    #2 0x440780 in grub_jpeg_decode_data ../video/readers/jpeg.c:617
    #3 0x440780 in grub_jpeg_decode_jpeg ../video/readers/jpeg.c:718
    #4 0x440780 in grub_video_reader_jpeg ../video/readers/jpeg.c:756
    . . .

0x61d00001f388 is located 0 bytes to the right of 2312-byte region [0x61d00001ea80,0x61d00001f388)
allocated by thread T0 here:
    #0 0x7f5460b0f7aa in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x987aa)
    #1 0x406862 in grub_malloc emu/mm.c:32
    #2 0x406862 in grub_zalloc emu/mm.c:43

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/renorobert/grub-2.00/grub-core/kern/misc.c:497 grub_memset
```

## huffman_payload.jpg

```
ASAN:SIGSEGV
=================================================================
==19141==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x000000442884 bp 0x0c3a00003e70 sp 0x7ffdbc84bd30 T0)
    #0 0x442883 in grub_jpeg_get_huff_code ../video/readers/jpeg.c:180
    #1 0x442883 in grub_jpeg_decode_du ../video/readers/jpeg.c:495
    #2 0x442883 in grub_jpeg_decode_data ../video/readers/jpeg.c:617
    #3 0x442883 in grub_jpeg_decode_jpeg ../video/readers/jpeg.c:718
    #4 0x442883 in grub_video_reader_jpeg ../video/readers/jpeg.c:756
. . .

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../video/readers/jpeg.c:180 grub_jpeg_get_huff_code
==19141==ABORTING
```
```
Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0xffff09f7ffff88f8 
RBX: 0x0 
RCX: 0x80 
RDX: 0xffff09f7ffff8878 
RSI: 0xf0 
RDI: 0x620580 --> 0x61e510 --> 0x0 
RBP: 0x7fffffffdd90 --> 0x7fffffffdde0 --> 0x7fffffffde40 --> 0x7fffffffde70 --> 0x7fffffffdeb0 --> 0x7fffffffdee0 (--> ...)
RSP: 0x7fffffffdd70 --> 0xf00000000 
RIP: 0x40b47a (<grub_jpeg_get_huff_code+141>:	movzx  eax,BYTE PTR [rax])
R8 : 0x0 
R9 : 0x0 
R10: 0x620b48 --> 0x8000000080 
R11: 0x246 
R12: 0x4011a0 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdfc0 --> 0x2 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40b473 <grub_jpeg_get_huff_code+134>:	add    eax,ecx
   0x40b475 <grub_jpeg_get_huff_code+136>:	cdqe   
   0x40b477 <grub_jpeg_get_huff_code+138>:	add    rax,rdx
=> 0x40b47a <grub_jpeg_get_huff_code+141>:	movzx  eax,BYTE PTR [rax]
   0x40b47d <grub_jpeg_get_huff_code+144>:	movzx  eax,al
   0x40b480 <grub_jpeg_get_huff_code+147>:	jmp    0x40b4a5 <grub_jpeg_get_huff_code+184>
   0x40b482 <grub_jpeg_get_huff_code+149>:	add    DWORD PTR [rbp-0x4],0x1
   0x40b486 <grub_jpeg_get_huff_code+153>:	cmp    DWORD PTR [rbp-0x4],0xf
```

## qt_selector_payload.jpg

```
ASAN:SIGSEGV
=================================================================
==19156==ERROR: AddressSanitizer: SEGV on unknown address 0x61d000022c80 (pc 0x000000440cb3 bp 0x0c3a00003e6e sp 0x7ffdab08a370 T0)
    #0 0x440cb2 in grub_jpeg_decode_du ../video/readers/jpeg.c:497
    #1 0x440cb2 in grub_jpeg_decode_data ../video/readers/jpeg.c:617
    #2 0x440cb2 in grub_jpeg_decode_jpeg ../video/readers/jpeg.c:718
    #3 0x440cb2 in grub_video_reader_jpeg ../video/readers/jpeg.c:756
. . .

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../video/readers/jpeg.c:497 grub_jpeg_decode_du
==19156==ABORTING
```

## rst_payload.jpg

```
=================================================================
==19180==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61700000ff80 at pc 0x000000444804 bp 0x7ffe6cf4c1c0 sp 0x7ffe6cf4c1b0
WRITE of size 1 at 0x61700000ff80 thread T0
    #0 0x444803 in grub_jpeg_ycrcb_to_rgb ../video/readers/jpeg.c:531
    #1 0x444803 in grub_jpeg_decode_data ../video/readers/jpeg.c:642
    #2 0x444803 in grub_jpeg_decode_jpeg ../video/readers/jpeg.c:718
    #3 0x444803 in grub_video_reader_jpeg ../video/readers/jpeg.c:756
. . .

0x61700000ff80 is located 0 bytes to the right of 768-byte region [0x61700000fc80,0x61700000ff80)
allocated by thread T0 here:
    #0 0x7fdb18b007aa in __interceptor_calloc (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x987aa)
    #1 0x406862 in grub_malloc emu/mm.c:32
    #2 0x406862 in grub_zalloc emu/mm.c:43
    #3 0x7ffe6cf4c5af  (<unknown module>)

SUMMARY: AddressSanitizer: heap-buffer-overflow ../video/readers/jpeg.c:531 grub_jpeg_ycrcb_to_rgb
```

## zigzag_global_oob_read.jpg

```
=================================================================
==19198==ERROR: AddressSanitizer: global-buffer-overflow on address 0x000000447701 at pc 0x0000004443e5 bp 0x7fff441564b0 sp 0x7fff441564a0
READ of size 1 at 0x000000447701 thread T0
    #0 0x4443e4 in grub_jpeg_decode_du ../video/readers/jpeg.c:510
    #1 0x4443e4 in grub_jpeg_decode_data ../video/readers/jpeg.c:617
    #2 0x4443e4 in grub_jpeg_decode_jpeg ../video/readers/jpeg.c:718
    #3 0x4443e4 in grub_video_reader_jpeg ../video/readers/jpeg.c:756
. . .

0x000000447701 is located 1 bytes to the right of global variable 'jpeg_zigzag_order' defined in '../video/readers/jpeg.c:57:27' (0x4476c0) of size 64
SUMMARY: AddressSanitizer: global-buffer-overflow ../video/readers/jpeg.c:510 grub_jpeg_decode_du
```

# PNG bugs

## grub_png_read_dynamic_block.png

```
=================================================================
==19213==ERROR: AddressSanitizer: global-buffer-overflow on address 0x00000041e9e0 at pc 0x00000041ace8 bp 0x7fff7df30b50 sp 0x7fff7df30b40
READ of size 4 at 0x00000041e9e0 thread T0
    #0 0x41ace7 in grub_png_read_dynamic_block ../video/readers/png.c:662
    #1 0x41b2cc in grub_png_decode_image_data ../video/readers/png.c:750
    #2 0x41b8de in grub_png_decode_png ../video/readers/png.c:817
    #3 0x41bcc2 in grub_video_reader_png ../video/readers/png.c:860
. . .

0x00000041e9e0 is located 4 bytes to the right of global variable 'cplens' defined in '../video/readers/png.c:302:18' (0x41e960) of size 124
0x00000041e9e0 is located 32 bytes to the left of global variable 'cplext' defined in '../video/readers/png.c:308:27' (0x41ea00) of size 31
SUMMARY: AddressSanitizer: global-buffer-overflow ../video/readers/png.c:662 grub_png_read_dynamic_block
```

## png_oob_write_idat.png
```
=================================================================
==19228==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61f00000ec20 at pc 0x00000041a1c1 bp 0x7fffbcdd5c30 sp 0x7fffbcdd5c20
WRITE of size 1 at 0x61f00000ec20 thread T0
    #0 0x41a1c0 in grub_png_output_byte ../video/readers/png.c:540
    #1 0x41b26f in grub_png_decode_image_data ../video/readers/png.c:736
    #2 0x41b8de in grub_png_decode_png ../video/readers/png.c:817
    #3 0x41bcc2 in grub_video_reader_png ../video/readers/png.c:860
. . .

0x61f00000ec20 is located 0 bytes to the right of 2976-byte region [0x61f00000e080,0x61f00000ec20)
allocated by thread T0 here:
    #0 0x7f073cdc0612 in malloc (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x98612)
    #1 0x403681 in grub_malloc emu/mm.c:32
    #2 0x4036be in grub_zalloc emu/mm.c:43
    #3 0x41760a in grub_video_bitmap_create ../video/bitmap.c:143
    #4 0x4186b9 in grub_png_decode_image_header ../video/readers/png.c:237
    #5 0x41b7f3 in grub_png_decode_png ../video/readers/png.c:809
    #6 0x41bcc2 in grub_video_reader_png ../video/readers/png.c:860
. . .

SUMMARY: AddressSanitizer: heap-buffer-overflow ../video/readers/png.c:540 grub_png_output_byte
```

## png_oob_write_iend.png

```
=================================================================
==19241==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x62300000f901 at pc 0x00000041b486 bp 0x7ffffca8a6a0 sp 0x7ffffca8a690
READ of size 1 at 0x62300000f901 thread T0
    #0 0x41b485 in grub_png_convert_image ../video/readers/png.c:784
    #1 0x41b97a in grub_png_decode_png ../video/readers/png.c:824
    #2 0x41bcc2 in grub_video_reader_png ../video/readers/png.c:860
. . .

0x62300000f901 is located 1 bytes to the right of 6144-byte region [0x62300000e100,0x62300000f900)
allocated by thread T0 here:
    #0 0x7f0b8057c612 in malloc (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x98612)
    #1 0x403681 in grub_malloc emu/mm.c:32
    #2 0x4189dd in grub_png_decode_image_header ../video/readers/png.c:259
    #3 0x41b7f3 in grub_png_decode_png ../video/readers/png.c:809
    #4 0x41bcc2 in grub_video_reader_png ../video/readers/png.c:860
. . .

SUMMARY: AddressSanitizer: heap-buffer-overflow ../video/readers/png.c:784 grub_png_convert_image
```
