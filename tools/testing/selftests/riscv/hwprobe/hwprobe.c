#include <asm/hwprobe.h>

/*
 * Rather than relying on having a new enough libc to define this, just do it
 * ourselves.  This way we don't need to be coupled to a new-enough libc to
 * contain the call.
 */
long riscv_hwprobe(struct riscv_hwprobe *pairs, long pair_count,
		   long key_offset, long cpu_count, unsigned long *cpus,
		   unsigned long flags);

int main(int argc, char **argv)
{
	struct riscv_hwprobe pairs[8];
	unsigned long cpus;
	long out;

	/* Fake the CPU_SET ops. */
	cpus = -1;

	/*
	 * Just run a basic test: pass enough pairs to get up to the base
	 * behavior, and then check to make sure it's sane.
	 */
	out = riscv_hwprobe(pairs, 8, 0, 1, &cpus, 0);
	if (out != 4)
	  return -1;
	for (long i = 0; i < out; ++i) {
	  if (pairs[i].key != RISCV_HWPROBE_KEY_BASE_BEHAVIOR)
	    continue;

	  if (pairs[i].val & RISCV_HWPROBE_BASE_BEHAVIOR_IMA)
	    continue;

	  return -2;
	}

	/*
	 * Check that offsets work by providing one that we know exists, and
	 * checking to make sure the resultig pair is what we asked for.
	 */
	out = riscv_hwprobe(pairs, 1, RISCV_HWPROBE_KEY_BASE_BEHAVIOR, 1, &cpus, 0);
	if (out != 1)
	  return -3;
	if (pairs[0].key != RISCV_HWPROBE_KEY_BASE_BEHAVIOR)
	  return -4;

	return 0;
}
