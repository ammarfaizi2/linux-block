#include <linux/linkage.h>
#include <linux/export.h>
#include <linux/init.h>

	.section ".rodata","a",%progbits

	.global VMLINUX_SYMBOL(intree_module_hashes)
VMLINUX_SYMBOL(intree_module_hashes):
	.incbin "certs/module_hashes.bin"
END(VMLINUX_SYMBOL(intree_module_hashes))
	.type VMLINUX_SYMBOL(intree_module_hashes), @object
	.global VMLINUX_SYMBOL(__end_intree_module_hashes)
VMLINUX_SYMBOL(__end_intree_module_hashes):
