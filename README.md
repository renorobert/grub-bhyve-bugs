# FreeBSD grub-bhyve bootloader virtual machine escapes – [CVE-2020-10565, CVE-2020-10566]

## Introduction

FreeBSD bhyve does not have legacy BIOS emulation [1] to start a VM using the full boot process. As an alternative to BIOS emulation, a userspace bootloader running as host process directly loads the kernel image into the guest memory, initializes the registers, sets up the descriptor states and exits cleanly. Later, the bhyve worker process resumes guest execution from the kernel entry point using the saved VM state. Two different bootloaders are used for this purpose depending on the Guest OS. FreeBSD guests are loaded using bhyveload [2], whereas non-FreeBSD guest operating systems are loaded using grub-bhyve [3]. grub-bhyve is a FreeBSD port based on GRUB emulator grub-emu. The grub-emu is modified to perform direct kernel boot in the absence of BIOS emulation. 

## Guest memory mapping 

FreeBSD bhyve uses libvmmapi API to interact with the hypervisor kernel module. grub-bhyve also uses the same interface. The emulation specific code can be found under grub-core/kern/emu. The main() function of grub emulator invokes grub_emu_bhyve_init() function to set up the guest memory for relocating the kernel image 

```c
[grub-core/kern/emu/main.c]

int
main (int argc, char *argv[])
{
  . . .
  if (grub_emu_bhyve_init(vmname, arguments.memsz) != 0)
  . . .
  /* XXX: This is a bit unportable.  */
  grub_util_biosdisk_init (arguments.dev_map);
  . . .
  /* Start GRUB!  */
  if (setjmp (main_env) == 0)
    grub_main ();
  . . .
  return 0;
}
```

grub_emu_bhyve_init() uses libvmmapi function vm_setup_memory() to map the guest memory into grub-bhyve process [4]. A pointer to the mapped guest memory can be obtained using vm_map_gpa(). 

```c
[grub-core/kern/emu/bhyve_hostif.c]

int
grub_emu_bhyve_init(const char *name, grub_uint64_t memsz)
{
. . .
  err = vm_create (name);
. . .
  bhyve_ctx = vm_open (name);
. . .
  err = vm_setup_memory (bhyve_ctx, memsz, VM_MMAP_ALL);
. . .
  lomemsz = vm_get_lowmem_limit(bhyve_ctx);

  /*
   * Extract the virtual address of the mapped guest memory.
   */
  if (memsz >= lomemsz) {
    bhyve_g2h.lomem = lomemsz;
    bhyve_g2h.himem = memsz - lomemsz;
    bhyve_g2h.himem_ptr = vm_map_gpa(bhyve_ctx, 4*GB, bhyve_g2h.himem);
  } else {
    bhyve_g2h.lomem = memsz;
    bhyve_g2h.himem = 0;    
  }
  bhyve_g2h.lomem_ptr = vm_map_gpa(bhyve_ctx, 0, bhyve_g2h.lomem);

 /*
   * bhyve is going to return the following memory segments
   *
   * 0 - 640K    - usable
   * 640K- 1MB   - vga hole, BIOS, not usable.
   * 1MB - lomem - usable
   * lomem - 4G  - not usable
   * 4G - himem  - usable [optional if himem != 0]
   */
  bhyve_info.nsegs = 2;
  bhyve_info.segs = bhyve_mm;

  bhyve_mm[0].start = 0x0;
  bhyve_mm[0].end = 640*1024;		/* 640K */
  bhyve_mm[0].type = GRUB_MEMORY_AVAILABLE;

  bhyve_mm[1].start = 1024*1024;
  bhyve_mm[1].end = (memsz > lomemsz) ? lomemsz : memsz;
  bhyve_mm[1].type = GRUB_MEMORY_AVAILABLE;

  if (memsz > lomemsz) {
    bhyve_info.nsegs++;
    bhyve_mm[2].start = 4*GB;
    bhyve_mm[2].end = (memsz - lomemsz) + bhyve_mm[2].start;
    bhyve_mm[2].type = GRUB_MEMORY_AVAILABLE;
  }
  . . .
}
```

The APIs to handle memory allocation and relocation are in grub-core/kern/emu/bhyve.c. The grub relocation code relies on usable memory segments to setup the boot environment. 

## Guest disk image 

The VM disk image to be used for file system operations is passed to grub_util_biosdisk_init() through dev_map argument in the main() function. The grub configuration file grub.cfg, the kernel image and initrd are all fetched from the guest disk image. The grub.cfg file from the disk image is parsed and executed by grub-bhyve for the boot process. This is where things get interesting. GRUB was designed to run in maximum privilege and trusts inputs from the operating system.  However, in the current design, due to the lack of BIOS emulation in hypervisor, GRUB emulator and the guest OS work across trust boundaries, exposing grub-bhyve to untrusted inputs from the guest OS. An untrusted guest can pass arbitrary grub commands to grub-bhyve process through grub.cfg file. 

## Memory management and relocation in grub-bhyve

Since FreeBSD uses jemalloc allocator for dynamic memory management, memory allocations performed by grub_malloc(), grub_zalloc(), grub_realloc() are also handled by the underlying allocator. The code for the same is found in grub-core/kern/emu/mm.c

The interesting part for analysis in the newly introduced code is the GRUB chunk management used for relocation. All of relocation code can be found in grub-core/kern/emu/bhyve.c. Some of the functions of interest are grub_relocator_alloc_chunk_addr(), grub_relocator_alloc_chunk_align() and get_virtual_current_address() as they involve chunk allocation and physical address translation based on inputs from the guest OS.

```c
[grub-core/kern/emu/bhyve.c]

SLIST_HEAD(grub_rlc_head, grub_relocator_chunk);

/* dummy struct for now */
struct grub_relocator
{
  struct grub_rlc_head head;
};

struct grub_relocator_chunk
{
  SLIST_ENTRY(grub_relocator_chunk) next;
  grub_phys_addr_t target;
  grub_size_t size;
};
```

grub_relocator_chunk has the target physical address where the data should be moved and the size of the allocation. Each chunk also has a next pointer to maintain a list of chunk allocation made. grub_relocator_alloc_chunk_addr() is the function used to reserve an allocation at a target physical address

```c
/* Return true if [point,point+size) is disjoint from [otarget,otarget+osize) */
static int
grub_relocator_disjoint(grub_phys_addr_t point, grub_size_t size,
		       grub_phys_addr_t otarget, grub_size_t osize)
{
  if ((point >= (otarget + osize)) || ((point + size) < otarget))
    return 1;

  return 0;
}

/* Return true if point is within [target, target+size) */
static int
grub_relocator_within(grub_phys_addr_t point, grub_phys_addr_t target,
                      grub_size_t size)
{
  if (point >= target && point < (target + size))
    return 1;

  return 0;
}
```

grub_relocator_disjoint() checks if a given physical address is already in the list of allocated chunks. `point` is the requested physical address and `size` is the chunk size requested for allocation. `otarget` and `osize` are the previously allocated chunk address and size. The condition `point >= (otarget + osize)` ensures newly requested chunk physical address starts beyond the current chunk in consideration and `(point + size) < otarget` ensures the new chunk is entirely below the start address of current chunk.

grub_relocator_within() checks if a given physical address is within a memory segment allocated by grub-bhyve. `point` is the physical address to be validated. `target` and `size` are the start address of a segment and its size value respectively.

```c
grub_err_t
grub_relocator_alloc_chunk_addr (struct grub_relocator *rel,
                                 grub_relocator_chunk_t *out,
                                 grub_phys_addr_t target, grub_size_t size)
{
  struct grub_relocator_chunk *cp, *ncp, *prev;
  grub_phys_addr_t end, ptarget;
  grub_size_t psize;
  grub_err_t err;
  int i;

  end = target + size - 1;
  *out = NULL;

  /*
   * Make sure there are no existing allocations that this request
   * overlaps with
   */
  SLIST_FOREACH(cp, &rel->head, next) {
    if (!grub_relocator_disjoint(target, size, cp->target, cp->size))
      {
	err = GRUB_ERR_BAD_ARGUMENT;
	goto done;
      }
  }

  /*
   * See if the allocation fits within physical segments
   */
  for (i = 0; i < binfo->nsegs; i++) {
    ptarget = binfo->segs[i].start;
    psize = binfo->segs[i].end - ptarget + 1;
    if (grub_relocator_within(target, ptarget, psize) &&
	grub_relocator_within(end, ptarget, psize))
      break;
  }

  if (i == binfo->nsegs) {
    err = GRUB_ERR_OUT_OF_RANGE;
    goto done;
  }

  /*
   * Located a memory segment: allocate a chunk and insert it into
   * the list
   */
  ncp = grub_zalloc (sizeof (struct grub_relocator_chunk));
  if (!ncp) {
    err = GRUB_ERR_OUT_OF_MEMORY;
    goto done;
  }
  
  ncp->target = target;
  ncp->size = size;

  /*
   * Insert at the head if the list is empty or the first element is
   * at a higher address
   */
  if (SLIST_EMPTY(&rel->head) || (SLIST_FIRST(&rel->head))->target > target) {
    SLIST_INSERT_HEAD(&rel->head, ncp, next);
  } else {
    /*
     * At least one element in the list that is less than target, so prev
     * is guaranteed to exist for the list insertion.
     */
    SLIST_FOREACH(cp, &rel->head, next) {
      if (cp->target > target) {
	break;
      }
      prev = cp;
    }
    SLIST_INSERT_AFTER(prev, ncp, next);
  }
  
  *out = ncp;
  err = 0;

 done:
  return err;
}
```

grub_relocator_alloc_chunk_addr() checks if the requested physical address and size is previously allocated as below:

```c
  SLIST_FOREACH(cp, &rel->head, next) {
    if (!grub_relocator_disjoint(target, size, cp->target, cp->size))
      {
	err = GRUB_ERR_BAD_ARGUMENT;
	goto done;
```
If the requested address is not part of any previously allocated chunks, the next step is to find if the requested address fits within any of grub-bhyve memory segments
```c
for (i = 0; i < binfo->nsegs; i++) {
    ptarget = binfo->segs[i].start;
    psize = binfo->segs[i].end - ptarget + 1;
    if (grub_relocator_within(target, ptarget, psize) &&
	grub_relocator_within(end, ptarget, psize))
      break;
  }
  ```

This loop ensures that both the start address as well as end address of a requested allocation fits within an available segment. The end address is calculated as `end = target + size - 1`. Once the allocation request is validated, chunk is allocated and added to the list. The list is ordered in the increasing value of address. grub_relocator_alloc_chunk_align() works in similar way, except it tries to get an aligned allocation within a range of address (min_addr to max_addr).

The relocations done using allocated chunk to setup the kernel image and other boot time structures in memory relies on get_virtual_current_address() to cast a physical address to a virtual address pointer. In case of grub-bhyve physical address is not equal to the virtual address. Hence the physical addresses are translated to the guest mapped pages by adding the base address of guest memory area. In grub-bhyve get_virtual_current_address() invokes grub_emu_bhyve_virt() to perform this translation.  

```c
[grub-core/kern/emu/bhyve.c]

void *
get_virtual_current_address (grub_relocator_chunk_t in)
{
  return grub_emu_bhyve_virt((grub_uint64_t)in->target);
}
```
```c
[grub-core/kern/emu/bhyve_hostif.c]

void *
grub_emu_bhyve_virt(grub_uint64_t physaddr)
{
  void *virt;

  virt = NULL;

  if (physaddr < bhyve_g2h.lomem)
    virt = (char *)bhyve_g2h.lomem_ptr + physaddr;
  else if (physaddr >= 4*GB && physaddr < (4*GB + bhyve_g2h.himem))
    virt = (char *)bhyve_g2h.himem_ptr + (physaddr - 4*GB);

  return (virt);
}
```

One potential issue with the validation in grub_relocator_alloc_chunk_addr() is the calculation involving end of requested physical address range. The line `end = target + size - 1` could overflow and further bypass the validation done by grub_relocator_within(). Thus, it might be possible to allocate a chunk with target physical address + size going past the guest mapped memory area. However, I did not explore this further since the guest memory allocated by vm_setup_memory() is protected by guard page [4]. Any linear overflow will hit the guard page.

## Boot handoff from grub-bhyve to bhyve worker process

grub-bhyve parses the grub.cfg file from the disk image and loads the kernel and initrd images when handling the linux and initrd commands. After the loading process, the VM state is setup during the boot command. The grub_relocator32_boot() function is meant to jump to the kernel entry point during the boot process. However, in the case of grub-bhyve, it invokes grub_emu_bhyve_boot32()

```c
[grub-core/kern/emu/bhyve.c]

/*
 * Boot handoff
 */
grub_err_t
grub_relocator32_boot (struct grub_relocator *rel,
		       struct grub_relocator32_state state,
		       int avoid_efi_bootservices __attribute__ ((unused)))
{
  grub_relocator_chunk_t ch;
  . . . 

  if (err == GRUB_ERR_NONE)
    grub_emu_bhyve_boot32(get_physical_target_address (ch), state);

  return err;
}
```

grub_emu_bhyve_boot32() saves the register and descriptor states using libvmmapi calls to the bhyve virtual machine monitor. Once the VM state is saved, the userspace bootloader exits cleanly using grub_reboot(). 

```c
[grub-core/kern/emu/bhyve_hostif.c]

void
grub_emu_bhyve_boot32(grub_uint32_t bt, struct grub_relocator32_state rs)
{
  . . .
  /*
   * "In 32-bit boot protocol, the kernel is started by jumping to the
   * 32-bit kernel entry point, which is the start address of loaded
   * 32/64-bit kernel."
   */
  assert(vm_set_register(bhyve_ctx, 0, VM_REG_GUEST_RIP, rs.eip) == 0);
  . . . 
 /*
   * Exit cleanly, using the conditional test to avoid the noreturn
   * warning.
   */
  if (bt)
    grub_reboot();
}
```

The saved VM state is later used by the bhyve worker process to start the guest execution from the kernel entry point. At this point we are moving into the bhyve source code. The bootstrap processor (BSP) or the vCPU0 starts the guest execution from the RIP set by grub-bhyve

```c
[bhyverun.c]

int
main(int argc, char *argv[])
{
	. . .
	ctx = do_open(vmname);
	. . .
	vm_set_memflags(ctx, memflags);
	err = vm_setup_memory(ctx, memsize, VM_MMAP_ALL);
	. . .
	error = vm_get_register(ctx, BSP, VM_REG_GUEST_RIP, &rip);
	. . .
	/*
	 * Add CPU 0
	 */
	fbsdrun_addcpu(ctx, BSP, BSP, rip);
	. . .
}

void
fbsdrun_addcpu(struct vmctx *ctx, int fromcpu, int newcpu, uint64_t rip)
{
	. . .
	/*
	 * Set up the vmexit struct to allow execution to start
	 * at the given RIP
	 */
	vmexit[newcpu].rip = rip;
	vmexit[newcpu].inst_length = 0;

	mt_vmm_info[newcpu].mt_ctx = ctx;
	mt_vmm_info[newcpu].mt_vcpu = newcpu;

	error = pthread_create(&mt_vmm_info[newcpu].mt_thr, NULL,
	    fbsdrun_start_thread, &mt_vmm_info[newcpu]);
	assert(error == 0);
}

static void *
fbsdrun_start_thread(void *param)
{
	. . .
        vm_loop(mtp->mt_ctx, vcpu, vmexit[vcpu].rip);

	/* not reached */
	exit(1);
	return (NULL);
}

static void
vm_loop(struct vmctx *ctx, int vcpu, uint64_t startrip)
{
	. . .
	error = vm_set_register(ctx, vcpu, VM_REG_GUEST_RIP, startrip);
	. . .
	while (1) {
		error = vm_run(ctx, vcpu, &vmexit[vcpu]);
		. . .
		exitcode = vmexit[vcpu].exitcode;
		. . .
		rc = (*handler[exitcode])(ctx, &vmexit[vcpu], &vcpu);
	. . .
}
```

The application processors (APs) or the rest of the vCPU threads are started by VMEXIT triggered during Startup IPI

```c
[bhyverun.c]

static vmexit_handler_t handler[VM_EXITCODE_MAX] = {
	. . .
	[VM_EXITCODE_SPINUP_AP] = vmexit_spinup_ap,
	. . .
};

static int
vmexit_spinup_ap(struct vmctx *ctx, struct vm_exit *vme, int *pvcpu)
{

	(void)spinup_ap(ctx, *pvcpu,
		    vme->u.spinup_ap.vcpu, vme->u.spinup_ap.rip);

	return (VMEXIT_CONTINUE);
}
```
```c
[spinup_ap.c]

int
spinup_ap(struct vmctx *ctx, int vcpu, int newcpu, uint64_t rip)
{
	. . .

	fbsdrun_addcpu(ctx, vcpu, newcpu, rip);

	return (newcpu);
}
```
```c
[sys/amd64/vmm/io/vlapic.c]

	if (mode == APIC_DELMODE_STARTUP) {
		if (vlapic->vcpuid == 0 && dest != 0 && dest < maxcpus) {
			vlapic2 = vm_lapic(vlapic->vm, dest);

			/*
			 * Ignore SIPIs in any state other than wait-for-SIPI
			 */
			if (vlapic2->boot_state != BS_SIPI)
				return (0);

			vlapic2->boot_state = BS_RUNNING;

			*retu = true;
			vmexit = vm_exitinfo(vlapic->vm, vlapic->vcpuid);
			vmexit->exitcode = VM_EXITCODE_SPINUP_AP;
			vmexit->u.spinup_ap.vcpu = dest;
			vmexit->u.spinup_ap.rip = vec << PAGE_SHIFT;

			return (0);
		}
	}
  ```


## Vulnerabilities in grub-bhyve

A couple of vulnerabilities were found in GRUB’s command handling - `loadfont` integer overflow when parsing PFF2 font (CVE-2020-10566) and memrw commands providing arbitrary read and write  (CVE-2020-10565). 

## CVE-2020-10566 – loadfont integer overflow 

GRUB uses loadfont command to load a specified PFF2 font file. The  loadfont command is registered in grub-core/font/font_cmd.c using grub_register_command() as below:

```c
    grub_register_command ("loadfont", loadfont_command,
			   N_("FILE..."),
			   N_("Specify one or more font files to load."));
```

The loadfont_command callback registered for the command is also part of the same file.
```c
static grub_err_t
loadfont_command (grub_command_t cmd __attribute__ ((unused)),
		  int argc,
		  char **args)
{
  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  while (argc--)
    if (grub_font_load (*args++) != 0)
      {
	if (!grub_errno)
	  return grub_error (GRUB_ERR_BAD_FONT, "invalid font");
	return grub_errno;
      }

  return GRUB_ERR_NONE;
}
```
The next function of interest is grub_font_load() function found in grub-core/font/font.c file which actually does the parsing of PFF2 files [5]. When handling font sections NAME and WEIG, read_section_as_string() is invoked to allocate the section length provided by font file and then copy the contents. 

```c
static char *
read_section_as_string (struct font_file_section *section)
{
  char *str;
  grub_ssize_t ret;

  str = grub_malloc (section->length + 1);
  if (!str)
    return 0;

  ret = grub_file_read (section->file, str, section->length);
	. . .
}

int
grub_font_load (const char *filename)
{
	. . .
      if (grub_memcmp (section.name, FONT_FORMAT_SECTION_NAMES_FONT_NAME,
		       sizeof (FONT_FORMAT_SECTION_NAMES_FONT_NAME) - 1) == 0)
	{
	  font->name = read_section_as_string (&section);
	  if (!font->name)
	    goto fail;
	. . .
}
```

When section->length is set to 0xFFFFFFFF, the size calculation for grub_malloc becomes 0 and jemalloc allocates a small buffer for this allocation request. When grub_file_read() tries to read 0xFFFFFFFF bytes from the font file, it results in a heap overflow. Moreover, grub_file_read() can read only until the end of font file and then returns. Thus, the heap overflow is controlled and does not end up as wild copy. In order to trigger the bug, use the attached grub.cfg and fontbug.pf2 files and reboot from the guest. 

```
root@guest:/boot/grub# rm grubenv
root@guest:/boot/grub# grub-editenv grubenv create
root@guest:/boot/grub# grub-editenv grubenv set run_fontbug=true
root@guest:/boot/grub# grub-editenv grubenv list
run_fontbug=true
```

The guest file system can also be mounted in host for debugging purpose like editing grub.cfg file in case something goes wrong and guest becomes unbootable

```
root@host:/vms/linux # mdconfig disk0.img 
md0
root@host:/vms/linux # fuse-ext2 -o rw+ /dev/md0s1 /mnt
root@host:/vms/linux # cd /mnt/boot/grub/
```
Below crash is noticed in the host

```
Reading symbols from grub-bhyve...done.
[New LWP 100159]
Core was generated by `/usr/local/sbin/grub-bhyve -c /dev/nmdm-linux.1A -m /vms/linux/device.map -M 512'.
Program terminated with signal SIGBUS, Bus error.
#0  0x0000000000454707 in grub_ext2_read_block (node=0x80331d168, fileblock=0xfc) at fs/ext2.c:392
392	  unsigned int blksz = EXT2_BLOCK_SIZE (data);
gdb-peda$ bt
#0  0x0000000000454707 in grub_ext2_read_block (node=0x80331d168, fileblock=0xfc) at fs/ext2.c:392
#1  0x0000000000459464 in grub_fshelp_read_file (disk=0x8033687c0, node=0x80331d168, read_hook=0x0, pos=0x400, len=0xffc00, 
    buf=0x80331d2b4 . . ., get_block=0x4546bc <grub_ext2_read_block>, filesize=0x100014, log2blocksize=0x3, blocks_start=0x0)
    at fs/fshelp.c:261
#2  0x0000000000454ee3 in grub_ext2_read_file (node=0x80331d168, read_hook=0x0, pos=0x400, len=0xffc00, buf=0x8032216b4 'A' <repeats 200 times>...) at fs/ext2.c:530
#3  0x00000000004558e3 in grub_ext2_read (file=0x803368740, buf=0x8032216b4 'A' <repeats 200 times>..., len=0xffc00) at fs/ext2.c:854
#4  0x000000000040c2b2 in grub_file_read (file=0x803368740, buf=0x8032216b4, len=0xffc00) at kern/file.c:158
#5  0x0000000000493822 in grub_bufio_read (file=0x803368800, buf=0x8032216b4 'A' <repeats 200 times>..., len=0xffc14) at io/bufio.c:146
#6  0x000000000040c2b2 in grub_file_read (file=0x803368800, buf=0x8032212c8, len=0x100000) at kern/file.c:158
#7  0x0000000000443bd2 in read_section_as_string (section=0x7fffffffe0c0) at font/font.c:387
#8  0x0000000000443fac in grub_font_load (filename=0x8033b28e0 "/boot/grub/fontbug.pf2") at font/font.c:548
#9  0x000000000044624b in loadfont_command (cmd=0x80322e400, argc=0x0, args=0x8033b28d0) at font/font_cmd.c:35
#10 0x00000000004b41a3 in grub_script_execute_cmdline (cmd=0x823c27788) at script/execute.c:927
. . .

gdb-peda$ x/i $rip
=> 0x454707 <grub_ext2_read_block+75>:	mov    eax,DWORD PTR [rax+0x18]
gdb-peda$ info registers 
rax            0x4141414141414141  0x4141414141414141
rbx            0x7fffffffe9c0      0x7fffffffe9c0
rcx            0x4546bc            0x4546bc
rdx            0xfc                0xfc
rsi            0xfc                0xfc
rdi            0x80331d168         0x80331d168
rbp            0x7fffffffde60      0x7fffffffde60
rsp            0x7fffffffdd50      0x7fffffffdd50
r8             0x80331c2b4         0x80331c2b4
r9             0x21                0x21
r10            0x1c9               0x1c9
r11            0x9                 0x9
r12            0x7fffffffe9b8      0x7fffffffe9b8
r13            0x0                 0x0
r14            0xa                 0xa
r15            0x7fffffffea18      0x7fffffffea18
rip            0x454707            0x454707 <grub_ext2_read_block+75>
eflags         0x10212             [ AF IF RF ]
cs             0x43                0x43
```

After rebooting the guest, run_fontbug environment variable is noticed to be set to false

```
renorobert@guest:/boot/grub$ grub-editenv grubenv list
run_fontbug=false
```

## CVE-2020-10565 – Arbitrary read/write to guest provided pointer using memrw

GRUB supports memrw command to read and write to anywhere is physical memory. The implementation for the same is found in grub-core/commands/memrw.c. In case of grub-bhyve, the guest physical address range is mapped within the virtual address space of the user space bootloader. When grub-bhyve directly uses the guest provided address, guest can read and write to anywhere in the virtual address space of grub-bhyve process. This reminds me of the network pointers 3D acceleration bug in VirtualBox [6] found by  Francisco Falcon (@fdfalcon)

In case of grub_cmd_read(), GRUB allows to save the output of read command to environment block which is accessible from the guest OS. 

```c
static grub_err_t
grub_cmd_read (grub_extcmd_context_t ctxt, int argc, char **argv)
{
  grub_addr_t addr;
  grub_uint32_t value = 0;
  char buf[sizeof ("XXXXXXXX")];
. . .
  addr = grub_strtoul (argv[0], 0, 0);
  switch (ctxt->extcmd->cmd->name[sizeof ("read_") - 1])
    {
    case 'd':
      value = *((volatile grub_uint32_t *) addr);
      break;

    case 'w':
      value = *((volatile grub_uint16_t *) addr);
      break;

    case 'b':
      value = *((volatile grub_uint8_t *) addr);
      break;
    }

  if (ctxt->state[0].set)
    {
      grub_snprintf (buf, sizeof (buf), "%x", value);
      grub_env_set (ctxt->state[0].arg, buf);
    }
  . . .
}
```

Similarly grub_cmd_write() allows guest to write to arbitrary address during boot.

```c
static grub_err_t
grub_cmd_write (grub_command_t cmd, int argc, char **argv)
{
  . . .
  switch (cmd->name[sizeof ("write_") - 1])
    {
    case 'd':
      if (mask != 0xffffffff)
	*((volatile grub_uint32_t *) addr)
	  = (*((volatile grub_uint32_t *) addr) & ~mask) | value;
      else
	*((volatile grub_uint32_t *) addr) = value;
      break;

    case 'w':
      if ((mask & 0xffff) != 0xffff)
	*((volatile grub_uint16_t *) addr)
	  = (*((volatile grub_uint16_t *) addr) & ~mask) | value;
      else
	*((volatile grub_uint16_t *) addr) = value;
      break;

    case 'b':
      if ((mask & 0xff) != 0xff)
	*((volatile grub_uint8_t *) addr)
	  = (*((volatile grub_uint8_t *) addr) & ~mask) | value;
      else
	*((volatile grub_uint8_t *) addr) = value;
      break;
    }

  return 0;
}
```

## Exploitation

The memrw vulnerability provides arbitrary read/write in grub-bhyve process which runs as root, without sandbox and does not have ASLR at the time of reporting the bug (FreeBSD 11.3). grub-bhyve was deprivileged later on along with the bug fix.

With arbitrary r/w in hand, I decided to modify the data structures used by boot command in grub-core/commands/boot.c

```c
struct grub_preboot
{
  grub_err_t (*preboot_func) (int);
  grub_err_t (*preboot_rest_func) (void);
  grub_loader_preboot_hook_prio_t prio;
  struct grub_preboot *next;
  struct grub_preboot *prev;
};

static int grub_loader_loaded;
static struct grub_preboot *preboots_head = 0,
  *preboots_tail = 0;

. . .

grub_err_t
grub_loader_boot (void)
{
  grub_err_t err = GRUB_ERR_NONE;
  struct grub_preboot *cur;

  if (! grub_loader_loaded)
    return grub_error (GRUB_ERR_NO_KERNEL,
		       N_("you need to load the kernel first"));

  if (grub_loader_flags & GRUB_LOADER_FLAG_NORETURN)
    grub_machine_fini ();

  for (cur = preboots_head; cur; cur = cur->next)
    {
      err = cur->preboot_func (grub_loader_flags);
```

The idea is to modify the `preboots_head` pointer to point to fake `grub_preboot` structure, and then hijack the execution during the call to `cur->preboot_func (grub_loader_flags)`. By overwriting `grub_loader_flags` with a pointer it is also possible to pass an argument to the hijacked function call. In this case, the `grub_preboot` structure was setup to call `longjmp()` with `grub_loader_flags` pointing to a fake `jmp_buf` to perform stack pivot. Then, shellcode already written to .bss segment is made executable using `mprotect()` and executed, which creates a file named VMESCAPE in the host. Finally, grub_reboot() in grub-core/kern/emu/main.c is invoked to cleanly exit grub-bhyve.

```
root@guest:/boot/grub# rm grubenv
root@guest:/boot/grub# grub-editenv grubenv create
root@guest:/boot/grub# grub-editenv grubenv set run_exploit=true
root@guest:/boot/grub# grub-editenv grubenv list
run_exploit=true
root@guest:/boot/grub# reboot
```
```
root@host:/ # vm list 
NAME   DATASTORE  LOADER  CPU  MEMORY  VNC  AUTOSTART  STATE
linux  default    grub    2    512M    -    No         Stopped

root@host:/ # file VMESCAPE
VMESCAPE: empty
```

## Notes on GRUB background_image 

As part of the review I also fuzzed and reviewed the JPEG and PNG parsers in GRUB, accessible through background_image command. The PoC’s to trigger the bugs are also part of this repo. Since grub-bhyve is compiled with --enable-grub-emu-sdl=no, there seems to be no active video adapter to further reach the vulnerable code.

## Disclosure

Font parser integer overflow bug was reported to FreeBSD on 29th November 2019 and memrw was reported on 8th February 2020. Both bugs were fixed on February 12th, 2020 [7]. The commands were disabled as they are not necessary for bhyve’s operation. A security advisory or erratum was not issued for these vulnerabilities since the FreeBSD Project does not maintain grub-bhyve. However, bug details were published as part of FreeBSD ports VuXML [8] and CVEs [9][10] were assigned by MITRE on request. 

A bunch of secure boot bypasses disclosed [11] recently may also be applicable to grub-bhyve as VMescapes. Moreover CVE-2020-14310 [12][13] affecting GRUB font parser is the same bug as CVE-2020-10566. To avoid VMescapes due to GRUB bugs, bhyve users should use UEFI boot ROM [14] instead of running grub emulator as a host process.

## References

[1] https://2013.asiabsdcon.org/papers/abc2013-P5A-paper.pdf        
[2] https://github.com/freebsd/freebsd/tree/master/usr.sbin/bhyveload    
[3] https://github.com/grehan-freebsd/grub2-bhyve     
[4] http://www.phrack.org/papers/escaping_from_freebsd_bhyve.html     
[5] http://grub.gibibit.com/New_font_format      
[6] https://www.coresecurity.com/sites/default/files/private-files/publications/2016/05/corelabs-Breaking_Out_of_VirtualBox_through_3D_Acceleration-Francisco_Falcon.pdf    
[7] https://svnweb.freebsd.org/ports?view=revision&revision=525916      
[8] https://www.vuxml.org/freebsd/9d6a48a7-4dad-11ea-8a1d-7085c25400ea.html      
[9] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10566      
[10] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10565       
[11] https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/GRUB2SecureBootBypass     
[12] https://people.canonical.com/~ubuntu-security/cve/2020/CVE-2020-14310       
[13] https://git.savannah.gnu.org/gitweb/?p=grub.git;a=blobdiff;f=grub-core/font/font.c;h=5edb477ac2e792a4ec5e773c1b6fbbf84a65b795;hp=8e118b315ce349a6ec557c97bdf6db76aa18007d;hb=3f05d693d1274965ffbe4ba99080dc2c570944c6;hpb=f725fa7cb2ece547c5af01eeeecfe8d95802ed41    
[14] https://www.freebsd.org/doc/handbook/virtualization-host-bhyve.html

