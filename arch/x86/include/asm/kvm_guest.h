#ifndef _ASM_X86_KVM_GUEST_H
#define _ASM_X86_KVM_GUEST_H

int kvm_setup_vsyscall_timeinfo(void);

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_ARCH_RANDOM)
extern bool kvm_get_rng_seed(u64 *rv);
#else
static inline bool kvm_get_rng_seed(u64 *rv)
{
	return false;
}
#endif

#endif /* _ASM_X86_KVM_GUEST_H */
