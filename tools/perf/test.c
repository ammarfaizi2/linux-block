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

#define PATH_MAX 100
#define MAXLINE 100


/* size of control buffer to send/recv one file descriptor */
#define CONTROLLEN  CMSG_LEN(sizeof(int))

static struct cmsghdr   *cmptr = NULL;      /* malloc'ed first time */

/*
 * Receive a file descriptor from a server process.  Also, any data
 * received is passed to (*userfunc)(STDERR_FILENO, buf, nbytes).
 * We have a 2-byte protocol for receiving the fd from send_fd().
 */
int
recv_fd(int fd ) /* , ssize_t (*userfunc)(int, const void *, size_t)) */
{
   int             newfd, nr, status;
   char            *ptr;
   char            buf[MAXLINE];
   struct iovec    iov[1];
   struct msghdr   msg;

   status = -1;
   for ( ; ; ) {
       iov[0].iov_base = buf;
       iov[0].iov_len  = sizeof(buf);
       msg.msg_iov     = iov;
       msg.msg_iovlen  = 1;
       msg.msg_name    = NULL;
       msg.msg_namelen = 0;
       if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
           return(-1);
       msg.msg_control    = cmptr;
       msg.msg_controllen = CONTROLLEN;
       if ((nr = recvmsg(fd, &msg, 0)) < 0) {
           perror("recvmsg error");
       } else if (nr == 0) {
           perror("connection closed by server");
           return(-1);
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

/*
        if (nr > 0 && (*userfunc)(STDERR_FILENO, buf, nr) != nr)
            return(-1);
*/

        if (status >= 0)    /* final data has arrived */
            return(newfd);  /* descriptor, or -status */
   }
}

static int fd;

static void sig_handler(int signum, siginfo_t *oh, void *uc)
{
	fprintf(stdout, "SIGIO\n");
	ioctl(fd, PERF_EVENT_IOC_REFRESH, 1);
}

int main(int argc, char **argv)
{
	struct sigaction sa;
	struct sockaddr_un addr;
	char path[PATH_MAX];
	char *dir;
	int sock, err;
	time_t start;

	dir = getenv("PERFSCRIPT_DIR");
	if (!dir) {
		fprintf(stderr, "failed to get PERFSCRIPT_DIR\n");
		return -1;
	}

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

	fd = recv_fd(sock);

	close(sock);

	fprintf(stdout, "got event fd %d\n", fd);

	fcntl(fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
	fcntl(fd, F_SETSIG, SIGIO);
	fcntl(fd, F_SETOWN, getpid());

	/* setup SIGIO signal handler */
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = (void *) sig_handler;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGIO, &sa, NULL) < 0) {
		perror("failed setting up signal handler\n");
		return -1;
	}

	ioctl(fd, PERF_EVENT_IOC_REFRESH, 1);

	start = time(NULL);
	while ((start + 1) > time(NULL)) {}

	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	return 0;
}
