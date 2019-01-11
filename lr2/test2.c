#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pwd.h>

#define N 10

int main() {
	int fd;
	int total;
	char buf[2*N + 1];
	
	buf[2*N] = '\0';
	fd = open("/dev/lr2_term2", O_RDONLY);
	if (fd == -1) {
		printf("Error! Unable to open the file!\n");
		return 1;	
	}
	total = read(fd, buf, 20);
	close(fd);
	printf("%d считано\n", total);
	printf("%s\n", buf);
	return 0;
}

// uid_t uid;
// pid_t pid;
// uid = getuid();
// pid = getpid();
// printf("uid is %d\npid is %d\n", uid, pid);
// int ret;
// ret = ioctl(fd, 1, pid);
// if (ret) {
// 	printf("Error! Unable to set pid!\n");
// 	return 1;	
// }
// ret = ioctl(fd, 3, 5);
// if (ret) {
// 	printf("Error! Unable to set buf_len!\n");
// 	return 1;	
// }	