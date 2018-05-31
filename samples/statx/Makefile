# List of programs to build
hostprogs-$(CONFIG_SAMPLE_STATX) := test-statx test-fsinfo

# Tell kbuild to always build the programs
always := $(hostprogs-y)

HOSTCFLAGS_test-statx.o += -I$(objtree)/usr/include

HOSTCFLAGS_test-fsinfo.o += -I$(objtree)/usr/include
HOSTLOADLIBES_test-fsinfo += -lm
