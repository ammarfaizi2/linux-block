#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/fs.h>

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	int dev_fd, prog_fd = -1;

	if (argc < 2) {
		fprintf(stderr, "Usage: iocost-attach BLKDEV [BPF_PROG]");
		return 1;
	}

	dev_fd = open(argv[1], O_RDONLY);
	if (dev_fd < 0) {
		perror("open(BLKDEV)");
		return 1;
	}

	if (argc > 2) {
		if (bpf_prog_load(argv[2], BPF_PROG_TYPE_IO_COST,
				  &obj, &prog_fd)) {
			perror("bpf_prog_load(BPF_PROG)");
			return 1;
		}
	}

	if (ioctl(dev_fd, BLKBPFIOCOST, (long)prog_fd)) {
		perror("ioctl(BLKBPFIOCOST)");
		return 1;
	}
	return 0;
}
