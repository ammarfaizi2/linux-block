#include <stdbool.h>
#include <stdio.h>
#include <wchar.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/errno.h>

#include "script-sample-api.h"

#include "Python.h"
#include <frameobject.h>

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

static bool  print;
static bool  printonly;
static char *printfile;
static char *dir;
static int   verbose;
static int   page_size;

#define PR_TASK_PERF_EVENTS_DATA_USER	48

typedef uint64_t u64;

struct mmap_stack {
	u64	cnt;
	u64	data[0];
};

static __thread struct mmap_stack *stack;
static __thread int fd_events;

#define HLIST_BITS 8
#define HLIST_SIZE (1 << HLIST_BITS)

static struct hlist_head heads[HLIST_SIZE];

struct hash_entry {
	struct hlist_node	 node;
	u64			 code;
};

static struct hash_entry* hash_find(void *code)
{
	struct hlist_head *head;
	struct hash_entry *h;
	int hash;

	hash = hash_64((u64) code, HLIST_BITS);
	head = &heads[hash];

	hlist_for_each_entry(h, head, node) {
		if (h->code == (u64) code)
			return h;
	}

	return NULL;
}

static int __store_event(PyFrameObject *frame)
{
#define BUF_MAX 4096
	PyCodeObject *co = frame->f_code;
	void *start = (void *) PyBytes_AS_STRING(co->co_code);
	u64   size  = (u64)    PyBytes_GET_SIZE(co->co_code);
	struct python_func *func;
	struct python_file *file;
	struct python_line *line;
	unsigned char *tab;
	ssize_t tab_size;
	wchar_t buf_name[BUF_MAX];
	char buf[PATH_MAX];
	static u64 id;
	int n, lineno;

	/* PYTHON_DUMP__FUNC */
	func = (struct python_func *) buf;

	PyUnicode_AsWideChar(co->co_name, buf_name, 100);
	lineno = PyCode_Addr2Line(frame->f_code, frame->f_lasti);

	n  = sizeof(*func);
	n += snprintf(func->name, PATH_MAX - sizeof(*func),
		      "%ls", buf_name);
	n  = PERF_ALIGN(n + 1, sizeof(u64));

	func->header.type = PYTHON_DUMP__FUNC;
	func->header.id   = id;
	func->header.size = n;
	func->start       = (u64) start;
	func->end         = (u64) start + size;
	func->line        = (u64) lineno;

	if (n != write(fd_events, func, n)) {
		perror("write failed");
		return -1;
	}

	if (verbose > 2) {
		fprintf(stdout, "perfsample func : %lu - %p-%p %s\n",
			id, start, start + size, func->name);
	}

	/* PYTHON_DUMP__FILE */
	file = (struct python_file *) buf;
	PyUnicode_AsWideChar(co->co_filename, buf_name, 100);

	n  = sizeof(*file);
	n += snprintf(file->name, PATH_MAX - sizeof(*file),
		      "%ls", buf_name);
	n  = PERF_ALIGN(n + 1, sizeof(u64));

	file->header.type = PYTHON_DUMP__FILE;
	file->header.id   = id;
	file->header.size = n;

	if (n != write(fd_events, file, n)) {
		perror("write failed");
		return -1;
	}

	if (verbose > 2) {
		fprintf(stdout, "perfsample file : %lu - %s\n",
			id, file->name);
	}

	/* PYTHON_DUMP__LINE */
	line = (struct python_line *) buf;

	tab = (unsigned char*) PyBytes_AS_STRING(co->co_lnotab);
	if (!tab) {
		fprintf(stdout, "failed: no line info for ID %lu\n", id);
		goto out;
	}

	tab_size = PyBytes_GET_SIZE(co->co_lnotab);
	if (tab_size >= (BUF_MAX - sizeof(*line) - 1)) {
		fprintf(stdout, "failed: line info too big for ID %lu\n", id);
		goto out;
	}

	memcpy(line->lnotab, tab, tab_size);

	n  = sizeof(*line);
	n += tab_size;
	n  = PERF_ALIGN(n, sizeof(u64));

	line->header.type = PYTHON_DUMP__LINE;
	line->header.id   = id;
	line->header.size = n;
	line->size        = tab_size;

	if (n != write(fd_events, line, n)) {
		perror("write failed");
		return -1;
	}

	if (verbose > 2) {
		fprintf(stdout, "perfsample line : \n");
	}

out:
	id++;
	return 0;

#undef BUF_MAX
}

static void store_event(PyFrameObject *frame)
{
	if (__store_event(frame))
		perror("event store failed");
}

static void hash_add(PyFrameObject *frame)
{
	PyCodeObject *co = frame->f_code;
	void *code = PyBytes_AS_STRING(co);
	struct hash_entry *h;
	int hash;

	if (hash_find(code))
		return;

	h = calloc(1, sizeof(*h));
	if (!h) {
		perror("failed: calloc");
		return;
	}

	h->code = (u64) code;

	hash = hash_64((u64) code, HLIST_BITS);
	hlist_add_head(&h->node, &heads[hash]);

	store_event(frame);
}

static void stack_push(PyFrameObject *frame)
{
	PyCodeObject *co = frame->f_code;
	u64 cnt = stack->cnt;

	stack->data[cnt] = (u64) PyBytes_AS_STRING(co->co_code);
	stack->cnt++;

	if (verbose > 2) {
		fprintf(stdout, "push %lu %p\n",
			stack->cnt, (void *) stack->data[cnt]);
	}

	hash_add(frame);
}

static void stack_pop(void)
{
	if (stack->cnt)
		stack->cnt--;

	if (verbose > 2) {
		fprintf(stdout, "pop  %lu %p\n",
			stack->cnt, (void*) stack->data[stack->cnt]);
	}
}

static void stack_line(PyFrameObject *frame)
{
	PyCodeObject *co = frame->f_code;

	if (!stack->cnt)
		stack_push(frame);

	stack->data[stack->cnt - 1] = (u64) PyBytes_AS_STRING(co->co_code) + frame->f_lasti;

	if (verbose > 2) {
		fprintf(stdout, "line %lu %p\n",
			stack->cnt, (void*) stack->data[stack->cnt]);
	}
}

static inline pid_t gettid(void)
{
	return (pid_t) syscall(__NR_gettid);
}

static int config(void)
{
	char *verb;

	print     = !!getenv("PERFSCRIPT_PRINT");
	printonly = !!getenv("PERFSCRIPT_PRINTONLY");
	printfile =   getenv("PERFSCRIPT_PRINTFILE");
	dir       =   getenv("PERFSCRIPT_DIR");
	verb      =   getenv("PERFSCRIPT_VERBOSE");
	verbose   =   verb ? atoi(verb) : 0;
	page_size =   sysconf(_SC_PAGE_SIZE);
	return 0;
}

static const char *what_str(unsigned int what)
{
	static const char *str[] = {
		"CALL",
		"EXCEPTION",
		"LINE",
		"RETURN",
		"C_CALL",
		"C_EXCEPTION",
		"C_RETURN",
	};

	if (what < 0 && what > 6)
		return "BUG";

	return str[what];
}

static FILE *trace_file(void)
{
	static FILE *fp;

	if (!fp) {
		if (printfile) {
			fp = fopen(printfile, "w+");
			if (!fp) {
				perror("failed to open print file\n");
				return NULL;
			}
		} else {
			fp = stderr;
		}
	}

	return fp;
}

static int trace_print(PyFrameObject *frame, int what)
{
	wchar_t buf_file[100], buf_name[100];
	PyObject *file, *name, *code;
	FILE *fp = trace_file();
	int lineno, idx;
	char *func;

	if (!fp || !frame || !frame->f_code)
		goto error;

	file = frame->f_code->co_filename;
	name = frame->f_code->co_name;
	code = frame->f_code->co_code;

	if (!file || !name || !code)
		goto error;

	PyUnicode_AsWideChar(file, buf_file, 100);
	PyUnicode_AsWideChar(name, buf_name, 100);

	lineno = PyCode_Addr2Line(frame->f_code, frame->f_lasti);
	func   = PyBytes_AS_STRING(code);
	idx    = frame->f_lasti != -1 ? frame->f_lasti : 0;

	fprintf(fp, "%-11s [%p+0x%05x] %ls %ls:%d\n",
		what_str(what), func, idx, buf_name, buf_file, lineno);

	fflush(NULL);
	return 0;

error:
	if (fp)
		fprintf(fp, "%-11s ERROR\n", what_str(what));
	return 0;
}

#define SOCKET_PATH_MAX 100
#define MAXLINE 100

/* size of control buffer to send/recv one file descriptor */
#define CONTROLLEN  CMSG_LEN(sizeof(int))

static struct cmsghdr   *cmptr = NULL;      /* malloc'ed first time */

int
recv_fd(int fd)
{
	int newfd, nr, status;
	char *ptr;
	char buf[MAXLINE];
	struct iovec iov[1];
	struct msghdr msg;

	status = -1;

	for ( ; ; ) {
		iov[0].iov_base = buf;
		iov[0].iov_len  = sizeof(buf);

		msg.msg_iov     = iov;
		msg.msg_iovlen  = 1;
		msg.msg_name    = NULL;
		msg.msg_namelen = 0;

		if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
			return -1;

		msg.msg_control    = cmptr;
		msg.msg_controllen = CONTROLLEN;

		if ((nr = recvmsg(fd, &msg, 0)) < 0) {
			perror("recvmsg error");
		} else if (nr == 0) {
			perror("connection closed by server");
			return -1;
		}

		/*
		* See if this is the final data with null & status.  Null
		* is next to last byte of buffer; status byte is last byte.
		* Zero status means there is a file descriptor to receive.
		*/
		for (ptr = buf; ptr < &buf[nr]; ) {
			if (*ptr++ == 0) {
				if (ptr != &buf[nr-1])
					fprintf(stderr, "message format error");

				status = *ptr & 0xFF;  /* prevent sign extension */
				if (status == 0) {
					if (msg.msg_controllen != CONTROLLEN)
						fprintf(stderr, "status = 0 but no fd");
					newfd = *(int *)CMSG_DATA(cmptr);
				} else {
					newfd = -status;
				}

				nr -= 2;
			}
		}

		if (status >= 0)    /* final data has arrived */
			return newfd;  /* descriptor, or -status */
	}
}

static int event_fd;

static int store_stack(void)
{
	struct python_header header;
	u32 n, n_stack;

	/* PYTHON_DUMP__STACK */
	n = sizeof(header) + sizeof(struct mmap_stack) + stack->cnt * sizeof(u64);
	n = PERF_ALIGN(n, sizeof(u64));

	header.type = PYTHON_DUMP__STACK;
	header.id   = 0;
	header.size = n;

	if (sizeof(header) != write(fd_events, &header, sizeof(header))) {
		perror("write failed");
		return -1;
	}

	n_stack = n - sizeof(header);

	if (n_stack != write(fd_events, (void *) stack, n_stack)) {
		perror("write failed");
		return -1;
	}

	return 0;
}

static int config_thread(void);

static void sig_handler(int signum, siginfo_t *oh, void *uc)
{
	if (!stack && config_thread()) {
		fprintf(stdout, "failed to configure stack\n");
		return;
	}

	if (store_stack())
		fprintf(stdout, "failed to store stack\n");

	ioctl(event_fd, PERF_EVENT_IOC_REFRESH, 1);
}

static int setup_socket(void)
{
	struct sigaction sa;
	struct sockaddr_un addr;
	char path[SOCKET_PATH_MAX];
	int sock, err;

	snprintf(path, sizeof(path), "%s/socket", dir);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

	err = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (err) {
		perror("connect error");
		return -1;
	}

	event_fd = recv_fd(sock);

	close(sock);

	if (verbose)
		fprintf(stdout, "got event fd %d\n", event_fd);

	fcntl(event_fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
	fcntl(event_fd, F_SETSIG, SIGIO);
	fcntl(event_fd, F_SETOWN, getpid());

	/* setup SIGIO signal handler */
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = (void *) sig_handler;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGIO, &sa, NULL) < 0) {
		perror("failed setting up signal handler\n");
		return -1;
	}

	return 0;
}

static int config_thread(void)
{
	int protection = PROT_READ | PROT_WRITE;
	int visibility = MAP_SHARED;
	char path[SOCKET_PATH_MAX];
	int err = -1, fd = -1;

	snprintf(path, SOCKET_PATH_MAX, "%s/datauser-%d", dir, gettid());

	fd = open(path, O_RDWR|O_CREAT, 0644);
	if (fd < 0) {
		perror("open failed");
		goto error;
	}

	if (ftruncate(fd, page_size)) {
		perror("ftruncate failed");
		goto error;
	}

	stack = mmap(NULL, page_size, protection, visibility, fd, 0);
	if ((void *) stack == MAP_FAILED) {
		perror("mmap failed");
		goto error;
	}

	stack->cnt = 0;

	snprintf(path, SOCKET_PATH_MAX, "%s/events-%d", dir, gettid());

	fd_events = open(path, O_RDWR|O_CREAT, 0644);
	if (fd_events < 0) {
		perror("open failed");
		goto error;
	}

	err = 0;

	if (verbose) {
		fprintf(stdout, "perfsample stack : %p\n", stack);
		fprintf(stdout, "perfsample dir   : %s\n", dir);
	}

	ioctl(event_fd, PERF_EVENT_IOC_REFRESH, 1);

error:
	if (err) {
		if (fd >= 0)
			close(fd);
		if (stack)
			munmap(stack, page_size);

		fprintf(stderr, "perfsample: failed to setup thread %d\n",
			gettid());
	}

	return err;
}

static int trace_dir(PyFrameObject *frame, int what)
{
	if (!stack && config_thread()) {
		fprintf(stdout, "failed to configure stack\n");
		return 0;
	}

	switch (what) {
	case PyTrace_CALL:
		stack_push(frame);
		break;
	case PyTrace_RETURN:
		stack_pop();
		break;
	case PyTrace_LINE:
		stack_line(frame);
		break;
	default:
		break;
	}
	return 0;
}

static int
trace(PyObject *self, PyFrameObject *frame, int what, PyObject *arg_unused)
{
	if (printonly)
		return trace_print(frame, what);
	if (dir) {
		if (print)
			trace_print(frame, what);

		return trace_dir(frame, what);
	}
	return 0;
}


#if PY_MAJOR_VERSION >= 3

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"perfsample",
	NULL,
	0,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

#define INITERROR return NULL

PyMODINIT_FUNC PyInit_perfsample(void)
#else
#define INITERROR return
void
initperfsample(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
	PyObject *module = PyModule_Create(&moduledef);
#else
	PyObject *module = Py_InitModule("perfsample", myextension_methods);
#endif

	if (module == NULL)
		INITERROR;

	if (config())
		INITERROR;

	if (setup_socket())
		INITERROR;

	fprintf(stderr, "perfsample initialized\n");
	PyEval_SetTrace((Py_tracefunc)trace, (PyObject*)module);

#if PY_MAJOR_VERSION >= 3
	return module;
#endif
}
