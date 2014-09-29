/*
 * Set up the VMAs to tell the VM about the vDSO.
 * Copyright 2007 Andi Kleen, SUSE Labs.
 * Subject to the GPL, v.2
 */
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <asm/vsyscall.h>
#include <asm/vgtod.h>
#include <asm/proto.h>
#include <asm/vdso.h>
#include <asm/page.h>
#include <asm/hpet.h>

#if defined(CONFIG_X86_64)
unsigned int __read_mostly vdso64_enabled = 1;

extern unsigned short vdso_sync_cpuid;
#endif

void __init init_vdso_image(const struct vdso_image *image)
{
	BUG_ON(image->size % PAGE_SIZE != 0);

	apply_alternatives((struct alt_instr *)(image->data + image->alt),
			   (struct alt_instr *)(image->data + image->alt +
						image->alt_len));
}

#if defined(CONFIG_X86_64)
static int __init init_vdso(void)
{
	init_vdso_image(&vdso_image_64);

#ifdef CONFIG_X86_X32_ABI
	init_vdso_image(&vdso_image_x32);
#endif

	return 0;
}
subsys_initcall(init_vdso);
#endif

struct linux_binprm;

/* Put the vdso above the (randomized) stack with another randomized offset.
   This way there is no hole in the middle of address space.
   To save memory make sure it is still in the same PTE as the stack top.
   This doesn't give that many random bits.

   Only used for the 64-bit and x32 vdsos. */
static unsigned long vdso_addr(unsigned long start, unsigned len)
{
#ifdef CONFIG_X86_32
	return 0;
#else
	unsigned long addr, end;
	unsigned offset;
	end = (start + PMD_SIZE - 1) & PMD_MASK;
	if (end >= TASK_SIZE_MAX)
		end = TASK_SIZE_MAX;
	end -= len;
	/* This loses some more bits than a modulo, but is cheaper */
	offset = get_random_int() & (PTRS_PER_PTE - 1);
	addr = start + (offset << PAGE_SHIFT);
	if (addr >= end)
		addr = end;

	/*
	 * page-align it here so that get_unmapped_area doesn't
	 * align it wrongfully again to the next page. addr can come in 4K
	 * unaligned here as a result of stack start randomization.
	 */
	addr = PAGE_ALIGN(addr);
	addr = align_vdso_addr(addr);

	return addr;
#endif
}

static void vvar_start_set(struct vm_special_mapping *sm,
			   struct mm_struct *mm, unsigned long start_addr)
{
	if (start_addr >= TASK_SIZE_MAX - mm->context.vdso_image->size) {
		/*
		 * We were just relocated out of bounds.  Malicious
		 * user code can cause this by mremapping only the
		 * first page of a multi-page vdso.
		 *
		 * We can't actually fail here, but it's not safe to
		 * allow vdso symbols to resolve to potentially
		 * non-canonical addresses.  Instead, just ignore
		 * the update.
		 */

		return;
	}

	mm->context.vvar_vma_start = start_addr;

	/*
	 * If we're here as a result of an mremap call, there are two
	 * major gotchas.  First, if that call came from the vdso, we're
	 * about to crash (i.e. don't do that).  Second, if we have more
	 * than one thread, this won't update the other threads.
	 */
	if (mm->context.vdso_image->sym_VDSO32_SYSENTER_RETURN)
		current_thread_info()->sysenter_return =
			VDSO_SYM_ADDR(current->mm, VDSO32_SYSENTER_RETURN);

}

static int vvar_fault(struct vm_special_mapping *sm,
		      struct vm_area_struct *vma, struct vm_fault *vmf)
{
	const struct vdso_image *image = vma->vm_mm->context.vdso_image;
	long sym_offset;
	int ret = -EFAULT;

	if (!image)
		return VM_FAULT_SIGBUS;
	sym_offset = (long)(vmf->pgoff << PAGE_SHIFT) +
		image->sym_vvar_start;

	/*
	 * Sanity check: a symbol offset of zero means that the page
	 * does not exist for this vdso image, not that the page is at
	 * offset zero relative to the text mapping.  This should be
	 * impossible here, because sym_offset should only be zero for
	 * the page past the end of the vvar mapping.
	 */
	if (sym_offset == 0)
		return VM_FAULT_SIGBUS;

	if (sym_offset == image->sym_vvar_page)
		ret = vm_insert_pfn(vma, (unsigned long)vmf->virtual_address,
				    __pa_symbol(&__vvar_page) >> PAGE_SHIFT);
#ifdef CONFIG_HPET_TIMER
	else if (hpet_address && sym_offset == image->sym_hpet_page)
		ret = vm_insert_pfn_prot(vma,
					 (unsigned long)vmf->virtual_address,
					 hpet_address >> PAGE_SHIFT,
					 pgprot_noncached(PAGE_READONLY));
#endif

	if (ret == 0)
		return VM_FAULT_NOPAGE;

	return VM_FAULT_SIGBUS;
}

static int vdso_fault(struct vm_special_mapping *sm,
		      struct vm_area_struct *vma, struct vm_fault *vmf)
{
	const struct vdso_image *image = vma->vm_mm->context.vdso_image;

	if (!image || (vmf->pgoff << PAGE_SHIFT) >= image->size)
		return VM_FAULT_SIGBUS;

	vmf->page = virt_to_page(image->data + (vmf->pgoff << PAGE_SHIFT));
	get_page(vmf->page);
	return 0;
}

static struct vm_special_mapping text_mapping = {
	.name = "[vdso]",
	.fault = vdso_fault,
};

static int map_vdso(const struct vdso_image *image, bool calculate_addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long addr, text_start;
	int ret = 0;
	static struct vm_special_mapping vvar_mapping = {
		.name = "[vvar]",
		.fault = vvar_fault,

		/*
		 * Tracking the vdso is roughly equivalent to tracking the
		 * vvar area, and the latter is slightly easier.
		 */
		.start_addr_set = vvar_start_set,
	};

	if (calculate_addr) {
		addr = vdso_addr(current->mm->start_stack,
				 image->size - image->sym_vvar_start);
	} else {
		addr = 0;
	}

	down_write(&mm->mmap_sem);

	addr = get_unmapped_area(NULL, addr,
				 image->size - image->sym_vvar_start, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	text_start = addr - image->sym_vvar_start;
	current->mm->context.vdso_image = image;

	/*
	 * MAYWRITE to allow gdb to COW and set breakpoints
	 */
	vma = _install_special_mapping(mm,
				       text_start,
				       image->size,
				       VM_READ|VM_EXEC|
				       VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC,
				       &text_mapping);

	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto up_fail;
	}

	vma = _install_special_mapping(mm,
				       addr,
				       -image->sym_vvar_start,
				       VM_READ|VM_MAYREAD|VM_IO|VM_DONTDUMP|
				       VM_PFNMAP,
				       &vvar_mapping);

	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto up_fail;
	}

up_fail:
	if (ret)
		current->mm->context.vdso_image = NULL;

	up_write(&mm->mmap_sem);
	return ret;
}

#if defined(CONFIG_X86_32) || defined(CONFIG_COMPAT)
static int load_vdso32(void)
{
	int ret;

	if (vdso32_enabled != 1)  /* Other values all mean "disabled" */
		return 0;

	ret = map_vdso(selected_vdso32, false);
	if (ret)
		return ret;

	return 0;
}
#endif

#ifdef CONFIG_X86_64
int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	if (!vdso64_enabled)
		return 0;

	return map_vdso(&vdso_image_64, true);
}

#ifdef CONFIG_COMPAT
int compat_arch_setup_additional_pages(struct linux_binprm *bprm,
				       int uses_interp)
{
#ifdef CONFIG_X86_X32_ABI
	if (test_thread_flag(TIF_X32)) {
		if (!vdso64_enabled)
			return 0;

		return map_vdso(&vdso_image_x32, true);
	}
#endif

	return load_vdso32();
}
#endif
#else
int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	return load_vdso32();
}
#endif

#ifdef CONFIG_X86_64
static __init int vdso_setup(char *s)
{
	vdso64_enabled = simple_strtoul(s, NULL, 0);
	return 0;
}
__setup("vdso=", vdso_setup);
#endif
