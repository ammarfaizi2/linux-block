#ifndef __HIGHBANK_CORE_H
#define __HIGHBANK_CORE_H

#ifdef CONFIG_PM_SLEEP
extern void highbank_pm_init(void);
#else
static inline void highbank_pm_init(void) {}
#endif

extern void highbank_smc1(int fn, int arg);

#endif
