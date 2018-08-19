/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Look at an ELF file's .note.gnu.property and determine if the file
 * supports shadow stack and/or indirect branch tracking.
 * The path from the ELF header to the note section is the following:
 * elfhdr->elf_phdr->elf_note->x86_note_gnu_property[].
 */

#include <asm/cet.h>
#include <asm/elf_property.h>
#include <uapi/linux/elf-em.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define ELF_NOTE_DESC_OFFSET(n, align) \
	round_up(sizeof(*n) + n->n_namesz, (align))

#define ELF_NOTE_NEXT_OFFSET(n, align) \
	round_up(ELF_NOTE_DESC_OFFSET(n, align) + n->n_descsz, (align))

static int find_cet(u8 *buf, u32 size, u32 align, int *shstk, int *ibt)
{
	unsigned long start = (unsigned long)buf;
	struct elf_note *note = (struct elf_note *)buf;

	*shstk = 0;
	*ibt = 0;

	/*
	 * Go through the x86_note_gnu_property array pointed by
	 * buf and look for shadow stack and indirect branch
	 * tracking features.
	 * The GNU_PROPERTY_X86_FEATURE_1_AND entry contains only
	 * one u32 as data.  Do not go beyond buf_size.
	 */

	while ((unsigned long) (note + 1) - start < size) {
		/* Find the NT_GNU_PROPERTY_TYPE_0 note. */
		if (note->n_namesz == 4 &&
		    note->n_type == NT_GNU_PROPERTY_TYPE_0 &&
		    memcmp(note + 1, "GNU", 4) == 0) {
			u8 *ptr, *ptr_end;

			/* Check for invalid property. */
			if (note->n_descsz < 8 ||
			   (note->n_descsz % align) != 0)
				return 0;

			/* Start and end of property array. */
			ptr = (u8 *)(note + 1) + 4;
			ptr_end = ptr + note->n_descsz;

			while (1) {
				u32 type = *(u32 *)ptr;
				u32 datasz = *(u32 *)(ptr + 4);

				ptr += 8;
				if ((ptr + datasz) > ptr_end)
					break;

				if (type == GNU_PROPERTY_X86_FEATURE_1_AND &&
				    datasz == 4) {
					u32 p = *(u32 *)ptr;

					if (p & GNU_PROPERTY_X86_FEATURE_1_SHSTK)
						*shstk = 1;
					if (p & GNU_PROPERTY_X86_FEATURE_1_IBT)
						*ibt = 1;
					return 1;
				}
			}
		}

		/*
		 * Note sections like .note.ABI-tag and .note.gnu.build-id
		 * are aligned to 4 bytes in 64-bit ELF objects.
		 */
		note = (void *)note + ELF_NOTE_NEXT_OFFSET(note, align);
	}

	return 0;
}

static int check_pt_note_segment(struct file *file,
				 unsigned long note_size, loff_t *pos,
				 u32 align, int *shstk, int *ibt)
{
	int retval;
	char *note_buf;

	/*
	 * Try to read in the whole PT_NOTE segment.
	 */
	note_buf = kmalloc(note_size, GFP_KERNEL);
	if (!note_buf)
		return -ENOMEM;
	retval = kernel_read(file, note_buf, note_size, pos);
	if (retval != note_size) {
		kfree(note_buf);
		return (retval < 0) ? retval : -EIO;
	}

	retval = find_cet(note_buf, note_size, align, shstk, ibt);
	kfree(note_buf);
	return retval;
}

#ifdef CONFIG_COMPAT
static int check_pt_note_32(struct file *file, struct elf32_phdr *phdr,
			    int phnum, int *shstk, int *ibt)
{
	int i;
	int found = 0;

	/*
	 * Go through all PT_NOTE segments and find NT_GNU_PROPERTY_TYPE_0.
	 */
	for (i = 0; i < phnum; i++, phdr++) {
		loff_t pos;

		/*
		 * NT_GNU_PROPERTY_TYPE_0 note is aligned to 4 bytes
		 * in 32-bit binaries.
		 */
		if ((phdr->p_type != PT_NOTE) || (phdr->p_align != 4))
			continue;

		pos = phdr->p_offset;
		found = check_pt_note_segment(file, phdr->p_filesz,
					      &pos, phdr->p_align,
					      shstk, ibt);
		if (found)
			break;
	}
	return found;
}
#endif

#ifdef CONFIG_X86_64
static int check_pt_note_64(struct file *file, struct elf64_phdr *phdr,
			    int phnum, int *shstk, int *ibt)
{
	int found = 0;

	/*
	 * Go through all PT_NOTE segments and find NT_GNU_PROPERTY_TYPE_0.
	 */
	for (; phnum > 0; phnum--, phdr++) {
		loff_t pos;

		/*
		 * NT_GNU_PROPERTY_TYPE_0 note is aligned to 8 bytes
		 * in 64-bit binaries.
		 */
		if ((phdr->p_type != PT_NOTE) || (phdr->p_align != 8))
			continue;

		pos = phdr->p_offset;
		found = check_pt_note_segment(file, phdr->p_filesz,
					      &pos, phdr->p_align,
					      shstk, ibt);

		if (found)
			break;
	}
	return found;
}
#endif

int arch_setup_features(void *ehdr_p, void *phdr_p,
			struct file *file, bool interp)
{
	int err = 0;
	int shstk = 0;
	int ibt = 0;

	struct elf64_hdr *ehdr64 = ehdr_p;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
		return 0;

	if (ehdr64->e_ident[EI_CLASS] == ELFCLASS64) {
		struct elf64_phdr *phdr64 = phdr_p;

		err = check_pt_note_64(file, phdr64, ehdr64->e_phnum,
				       &shstk, &ibt);
		if (err < 0)
			goto out;
	} else {
#ifdef CONFIG_COMPAT
		struct elf32_hdr *ehdr32 = ehdr_p;

		if (ehdr32->e_ident[EI_CLASS] == ELFCLASS32) {
			struct elf32_phdr *phdr32 = phdr_p;

			err = check_pt_note_32(file, phdr32, ehdr32->e_phnum,
					       &shstk, &ibt);
			if (err < 0)
				goto out;
		}
#endif
	}

	current->thread.cet.shstk_enabled = 0;
	current->thread.cet.shstk_base = 0;
	current->thread.cet.shstk_size = 0;
	if (cpu_feature_enabled(X86_FEATURE_SHSTK)) {
		if (shstk) {
			err = cet_setup_shstk();
			if (err < 0)
				goto out;
		}
	}
out:
	return err;
}
