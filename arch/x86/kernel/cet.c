/* SPDX-License-Identifier: GPL-2.0 */
/*
 * cet.c - Control Flow Enforcement (CET)
 *
 * Copyright (c) 2018, Intel Corporation.
 * Yu-cheng Yu <yu-cheng.yu@intel.com>
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <asm/msr.h>
#include <asm/user.h>
#include <asm/fpu/xstate.h>
#include <asm/fpu/types.h>
#include <asm/cet.h>
<<<<<<< ours
#include <asm/special_insns.h>
=======
>>>>>>> theirs

#define SHSTK_SIZE (0x8000 * (test_thread_flag(TIF_IA32) ? 4 : 8))

static inline int cet_set_shstk_ptr(unsigned long addr)
{
	u64 r;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
		return -1;

	if ((addr >= TASK_SIZE) || (!IS_ALIGNED(addr, 4)))
		return -1;

	rdmsrl(MSR_IA32_U_CET, r);
	wrmsrl(MSR_IA32_U_CET, r | MSR_IA32_CET_SHSTK_EN);
	wrmsrl(MSR_IA32_PL3_SSP, addr);
	return 0;
}

unsigned long cet_get_shstk_ptr(void)
{
	unsigned long ptr;

	if (!current->thread.cet.shstk_enabled)
		return 0;

	rdmsrl(MSR_IA32_PL3_SSP, ptr);
	return ptr;
}

<<<<<<< ours
int cet_push_shstk(int ia32, unsigned long ssp, unsigned long val)
{
	if (val >= TASK_SIZE)
		return -EINVAL;

	if (IS_ENABLED(CONFIG_IA32_EMULATION) && ia32) {
		if (!IS_ALIGNED(ssp, 4))
			return -EINVAL;
		cet_set_shstk_ptr(ssp);
		return write_user_shstk_32(ssp, (unsigned int)val);
	} else {
		if (!IS_ALIGNED(ssp, 8))
			return -EINVAL;
		cet_set_shstk_ptr(ssp);
		return write_user_shstk_64(ssp, val);
	}
}

=======
>>>>>>> theirs
static unsigned long shstk_mmap(unsigned long addr, unsigned long len)
{
	struct mm_struct *mm = current->mm;
	unsigned long populate;

	down_write(&mm->mmap_sem);
	addr = do_mmap(NULL, addr, len, PROT_READ,
		       MAP_ANONYMOUS | MAP_PRIVATE, VM_SHSTK,
		       0, &populate, NULL);
	up_write(&mm->mmap_sem);

	if (populate)
		mm_populate(addr, populate);

	return addr;
}

int cet_setup_shstk(void)
{
	unsigned long addr, size;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
		return -EOPNOTSUPP;

	size = SHSTK_SIZE;
	addr = shstk_mmap(0, size);

	if (addr >= TASK_SIZE)
		return -ENOMEM;

	cet_set_shstk_ptr(addr + size - sizeof(void *));
	current->thread.cet.shstk_base = addr;
	current->thread.cet.shstk_size = size;
	current->thread.cet.shstk_enabled = 1;
	return 0;
}

void cet_disable_shstk(void)
{
	u64 r;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
		return;

	rdmsrl(MSR_IA32_U_CET, r);
	r &= ~(MSR_IA32_CET_SHSTK_EN);
	wrmsrl(MSR_IA32_U_CET, r);
	wrmsrl(MSR_IA32_PL3_SSP, 0);
	current->thread.cet.shstk_enabled = 0;
}

void cet_disable_free_shstk(struct task_struct *tsk)
{
	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) ||
	    !tsk->thread.cet.shstk_enabled)
		return;

	if (tsk == current)
		cet_disable_shstk();

	/*
	 * Free only when tsk is current or shares mm
	 * with current but has its own shstk.
	 */
	if (tsk->mm && (tsk->mm == current->mm) &&
	    (tsk->thread.cet.shstk_base)) {
		vm_munmap(tsk->thread.cet.shstk_base,
			  tsk->thread.cet.shstk_size);
		tsk->thread.cet.shstk_base = 0;
		tsk->thread.cet.shstk_size = 0;
	}

	tsk->thread.cet.shstk_enabled = 0;
}
<<<<<<< ours

int cet_restore_signal(unsigned long ssp)
{
	if (!current->thread.cet.shstk_enabled)
		return 0;
	return cet_set_shstk_ptr(ssp);
}

int cet_setup_signal(int ia32, unsigned long rstor_addr)
{
	unsigned long ssp;
	struct cet_stat *cet = &current->thread.cet;

	if (!current->thread.cet.shstk_enabled)
		return 0;

	ssp = cet_get_shstk_ptr();

	/*
	 * Put the restorer address on the shstk
	 */
	if (ia32)
		ssp -= sizeof(u32);
	else
		ssp -= sizeof(rstor_addr);

	if (ssp >= (cet->shstk_base + cet->shstk_size) ||
	    ssp < cet->shstk_base)
		return -EINVAL;

	return cet_push_shstk(ia32, ssp, rstor_addr);
}
=======
>>>>>>> theirs
