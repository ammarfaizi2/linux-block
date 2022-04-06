# SPDX-License-Identifier: GPL-2.0-only
lib-y  := usercopy.o delay.o
obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
ifneq ($(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS), y)
lib-y  += string.o
endif
