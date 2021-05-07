# SPDX-License-Identifier: GPL-2.0

TOPDIR = ../..
include $(TOPDIR)/include/builddefs

BINS = idmapped-mounts mount-idmapped
LINKS = fscaps-in-ancestor-userns nested-userns
TARGETS = $(BINS) $(LINKS)
CFILES_IDMAPPED_MOUNTS = idmapped-mounts.c utils.c
CFILES_MOUNT_IDMAPPED = mount-idmapped.c utils.c

HFILES = missing.h utils.h
LLDLIBS += -pthread
LDIRT = $(TARGETS)

ifeq ($(HAVE_LIBCAP), true)
LLDLIBS += -lcap
endif

ifeq ($(HAVE_URING), true)
LLDLIBS += -luring
endif

default: depend $(TARGETS)

depend: .dep

include $(BUILDRULES)

idmapped-mounts: $(CFILES_IDMAPPED_MOUNTS)
	@echo "    [CC]    $@"
	$(Q)$(LTLINK) $(CFILES_IDMAPPED_MOUNTS) -o $@ $(CFLAGS) $(LDFLAGS) $(LDLIBS)

fscaps-in-ancestor-userns:
	ln -sf idmapped-mounts fscaps-in-ancestor-userns

nested-userns:
	ln -sf idmapped-mounts nested-userns

mount-idmapped: $(CFILES_MOUNT_IDMAPPED)
	@echo "    [CC]    $@"
	$(Q)$(LTLINK) $(CFILES_MOUNT_IDMAPPED) -o $@ $(CFLAGS) $(LDFLAGS) $(LDLIBS)

install:
	$(INSTALL) -m 755 -d $(PKG_LIB_DIR)/src/idmapped-mounts
	$(INSTALL) -m 755 $(BINS) $(PKG_LIB_DIR)/src/idmapped-mounts
	cd $(PKG_LIB_DIR)/src/idmapped-mounts && \
		rm -f $(LINKS) && \
		$(LN_S) idmapped-mounts fscaps-in-ancestor-userns && \
		$(LN_S) idmapped-mounts nested-userns

-include .dep
