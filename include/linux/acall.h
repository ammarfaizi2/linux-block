#ifndef __LINUX_ACALL_H
#define __LINUX_ACALL_H

struct acall_submission {
	u16 flags;
	u16 nr;
	u32 id;
	u64 cookie;
	u64 args[6];
};

struct acall_result {
	u64 cookie;
	u64 return_code;
};

#endif
