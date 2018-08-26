/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/prctl.h>
#include <linux/compat.h>
#include <asm/processor.h>
#include <asm/prctl.h>
#include <asm/elf.h>
#include <asm/elf_property.h>
#include <asm/cet.h>

/*
 * Handler of prctl for CET:
 *
 * ARCH_CET_STATUS: return the current status
 * ARCH_CET_DISABLE: disable features
 * ARCH_CET_LOCK: lock out cet features until exec()
 * ARCH_CET_EXEC: set default features for exec()
 * ARCH_CET_ALLOC_SHSTK: allocate shadow stack
 * ARCH_CET_PUSH_SHSTK: put a return address on shadow stack
 */

static int handle_get_status(unsigned long arg2)
{
	unsigned int features = 0, cet_exec = 0;
	unsigned long shstk_size = 0;

	if (current->thread.cet.shstk_enabled)
		features |= GNU_PROPERTY_X86_FEATURE_1_SHSTK;
	if (current->thread.cet.exec_shstk == CET_EXEC_ALWAYS_ON)
		cet_exec |= GNU_PROPERTY_X86_FEATURE_1_SHSTK;
	shstk_size = current->thread.cet.exec_shstk_size;

	if (in_compat_syscall()) {
		unsigned int buf[3];

		buf[0] = features;
		buf[1] = cet_exec;
		buf[2] = (unsigned int)shstk_size;
		return copy_to_user((unsigned int __user *)arg2, buf,
				    sizeof(buf));
	} else {
		unsigned long buf[3];

		buf[0] = (unsigned long)features;
		buf[1] = (unsigned long)cet_exec;
		buf[2] = shstk_size;
		return copy_to_user((unsigned long __user *)arg2, buf,
				    sizeof(buf));
	}
}

static int handle_set_exec(unsigned long arg2)
{
	unsigned int features = 0, cet_exec = 0;
	unsigned long shstk_size = 0;
	int err = 0;

	if (in_compat_syscall()) {
		unsigned int buf[3];

		err = copy_from_user(buf, (unsigned int __user *)arg2,
				     sizeof(buf));
		if (!err) {
			features = buf[0];
			cet_exec = buf[1];
			shstk_size = (unsigned long)buf[2];
		}
	} else {
		unsigned long buf[3];

		err = copy_from_user(buf, (unsigned long __user *)arg2,
				     sizeof(buf));
		if (!err) {
			features = (unsigned int)buf[0];
			cet_exec = (unsigned int)buf[1];
			shstk_size = buf[2];
		}
	}

	if (err)
		return -EFAULT;
	if (cet_exec > CET_EXEC_MAX)
		return -EINVAL;
	if (shstk_size >= TASK_SIZE)
		return -EINVAL;

	if (features & GNU_PROPERTY_X86_FEATURE_1_SHSTK) {
		if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
			return -EINVAL;
		if ((current->thread.cet.exec_shstk == CET_EXEC_ALWAYS_ON) &&
		    (cet_exec != CET_EXEC_ALWAYS_ON))
			return -EPERM;
	}

	if (features & GNU_PROPERTY_X86_FEATURE_1_SHSTK)
		current->thread.cet.exec_shstk = cet_exec;

	current->thread.cet.exec_shstk_size = shstk_size;
	return 0;
}

static int handle_push_shstk(unsigned long arg2)
{
	unsigned long ssp = 0, ret_addr = 0;
	int ia32, err;

	ia32 = in_ia32_syscall();

	if (ia32) {
		unsigned int buf[2];

		err = copy_from_user(buf, (unsigned int __user *)arg2,
				     sizeof(buf));
		if (!err) {
			ssp = (unsigned long)buf[0];
			ret_addr = (unsigned long)buf[1];
		}
	} else {
		unsigned long buf[2];

		err = copy_from_user(buf, (unsigned long __user *)arg2,
				     sizeof(buf));
		if (!err) {
			ssp = buf[0];
			ret_addr = buf[1];
		}
	}
	if (err)
		return -EFAULT;
	err = cet_push_shstk(ia32, ssp, ret_addr);
	if (err)
		return -err;
	return 0;
}

static int handle_alloc_shstk(unsigned long arg2)
{
	int err = 0;
	unsigned long shstk_size = 0;

	if (in_ia32_syscall()) {
		unsigned int size;

		err = get_user(size, (unsigned int __user *)arg2);
		if (!err)
			shstk_size = size;
	} else {
		err = get_user(shstk_size, (unsigned long __user *)arg2);
	}

	if (err)
		return -EFAULT;

	err = cet_alloc_shstk(&shstk_size);
	if (err)
		return -err;

	if (in_ia32_syscall()) {
		if (put_user(shstk_size, (unsigned int __user *)arg2))
			return -EFAULT;
	} else {
		if (put_user(shstk_size, (unsigned long __user *)arg2))
			return -EFAULT;
	}
	return 0;
}

int prctl_cet(int option, unsigned long arg2)
{
	if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
		return -EINVAL;

	switch (option) {
	case ARCH_CET_STATUS:
		return handle_get_status(arg2);

	case ARCH_CET_DISABLE:
		if (current->thread.cet.locked)
			return -EPERM;
		if (arg2 & GNU_PROPERTY_X86_FEATURE_1_SHSTK)
			cet_disable_free_shstk(current);

		return 0;

	case ARCH_CET_LOCK:
		current->thread.cet.locked = 1;
		return 0;

	case ARCH_CET_EXEC:
		return handle_set_exec(arg2);

	case ARCH_CET_ALLOC_SHSTK:
		return handle_alloc_shstk(arg2);

	case ARCH_CET_PUSH_SHSTK:
		return handle_push_shstk(arg2);

	default:
		return -EINVAL;
	}
}
