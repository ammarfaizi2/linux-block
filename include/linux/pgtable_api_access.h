/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGTABLE_API_ACCESS_H
#define _LINUX_PGTABLE_API_ACCESS_H

#include <asm/pgtable_api_access.h>

#ifndef pte_access_permitted
#define pte_access_permitted(pte, write) \
	(pte_present(pte) && (!(write) || pte_write(pte)))
#endif

#ifndef pmd_access_permitted
#define pmd_access_permitted(pmd, write) \
	(pmd_present(pmd) && (!(write) || pmd_write(pmd)))
#endif

#ifndef pud_access_permitted
#define pud_access_permitted(pud, write) \
	(pud_present(pud) && (!(write) || pud_write(pud)))
#endif

#ifndef p4d_access_permitted
#define p4d_access_permitted(p4d, write) \
	(p4d_present(p4d) && (!(write) || p4d_write(p4d)))
#endif

#ifndef pgd_access_permitted
#define pgd_access_permitted(pgd, write) \
	(pgd_present(pgd) && (!(write) || pgd_write(pgd)))
#endif

#endif /* _LINUX_PGTABLE_API_ACCESS_H */
