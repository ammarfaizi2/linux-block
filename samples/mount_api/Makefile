# List of programs to build
hostprogs-$(CONFIG_SAMPLE_MOUNT_API) := test-fsmount

# Tell kbuild to always build the programs
always := $(hostprogs-y)

HOSTCFLAGS_test-fsmount.o += -I$(objtree)/usr/include
