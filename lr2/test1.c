#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pwd.h>
//#include <errno.h> 
#define N 10

int main() {
	int fd;
	int total;
	const char buf[2*N] = "1a2b3c4d5e6f7g8h9i0j";
	
	fd = open("/dev/lr2_term2", O_WRONLY);
	if (fd == -1) {
		printf("Error! Unble to open the file!\n");
		return 1;	
	}
	total = write(fd, buf, 20);
	close(fd);
	printf("%d записано\n", total);
	return 0;
}


	
//	int ret;
// printf("uid is %d\npid is %d\n", uid, pid);
// ret = ioctl(fd, 1, pid);
// if (ret) {
// 	printf("Error! Unble to set pid!\n");
// 	return 1;	
// }

// printf("%s\n", buf);