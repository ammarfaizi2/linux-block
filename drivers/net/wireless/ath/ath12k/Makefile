# SPDX-License-Identifier: BSD-3-Clause-Clear
obj-$(CONFIG_ATH12K) += ath12k.o
ath12k-y += core.o \
	    hal.o \
	    hal_tx.o \
	    hal_rx.o \
	    wmi.o \
	    mac.o \
	    reg.o \
	    htc.o \
	    qmi.o \
	    dp.o  \
	    dp_tx.o \
	    dp_rx.o \
	    debug.o \
	    ce.o \
	    peer.o \
	    dbring.o \
	    hw.o \
	    wow.o \
	    mhi.o \
	    pci.o \
	    dp_mon.o

ath12k-$(CONFIG_ATH12K_DEBUGFS) += debugfs.o debugfs_htt_stats.o debugfs_sta.o
ath12k-$(CONFIG_NL80211_TESTMODE) += testmode.o
ath12k-$(CONFIG_ATH12K_TRACING) += trace.o
ath12k-$(CONFIG_THERMAL) += thermal.o
ath12k-$(CONFIG_ATH12K_SPECTRAL) += spectral.o

# for tracing framework to find trace.h
CFLAGS_trace.o := -I$(src)
