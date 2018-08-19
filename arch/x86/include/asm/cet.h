/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CET_H
#define _ASM_X86_CET_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

struct task_struct;
/*
 * Per-thread CET status
 */
struct cet_stat {
	unsigned long	shstk_base;
	unsigned long	shstk_size;
	unsigned int	shstk_enabled:1;
};

#ifdef CONFIG_X86_INTEL_CET
unsigned long cet_get_shstk_ptr(void);
int cet_push_shstk(int ia32, unsigned long ssp, unsigned long val);
int cet_setup_shstk(void);
int cet_setup_thread_shstk(struct task_struct *p);
void cet_disable_shstk(void);
void cet_disable_free_shstk(struct task_struct *p);
int cet_restore_signal(unsigned long ssp);
int cet_setup_signal(int ia32, unsigned long addr);
#else
static inline unsigned long cet_get_shstk_ptr(void) { return 0; }
static inline int cet_push_shstk(int ia32, unsigned long ssp,
				 unsigned long val) { return 0; }
static inline int cet_setup_shstk(void) { return 0; }
static inline int cet_setup_thread_shstk(struct task_struct *p) { return 0; }
static inline void cet_disable_shstk(void) {}
static inline void cet_disable_free_shstk(struct task_struct *p) {}
static inline int cet_restore_signal(unsigned long ssp) { return 0; }
static inline int cet_setup_signal(int ia32, unsigned long addr) { return 0; }
int cet_setup_shstk(void);
void cet_disable_shstk(void);
void cet_disable_free_shstk(struct task_struct *p);
#else
static inline unsigned long cet_get_shstk_ptr(void) { return 0; }
static inline int cet_setup_shstk(void) { return 0; }
static inline void cet_disable_shstk(void) {}
static inline void cet_disable_free_shstk(struct task_struct *p) {}
#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CET_H */
