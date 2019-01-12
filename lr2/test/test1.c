#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>

void print_buf(char *buf, int size) {
	int i;
	for (i = 0; i < size; ++i) {
		printf("%c", buf[i]);
	}
	printf("\n");
	return;
}

int main(int argc, char *argv[]) {
	long unsigned etalon = atol(argv[2]);
	int N = atoi(argv[3]);
	int in, fd;
	int ret;
	long unsigned total = 0;
	int cnt = 0;
	char* buf;

	buf = (char *)calloc(N + 1, sizeof(char));
	if (buf == NULL) {
		printf("Error! Unable to allocate memory!\n");
		return -1;
	} 
	buf[N] = '\0';
	in = open(argv[1], O_RDONLY);
	fd = open("/dev/lr2_term2", O_WRONLY);
	if ((in == -1) || (fd == -1)) {
		goto errOpen;
	}
	while (total != etalon) {
		++cnt;
		if (cnt == 1000) {
			ret = ioctl(fd, 1, 1);
			ret = ioctl(fd, 1, 10);
			ret = ioctl(fd, 1, 50);
			ret = ioctl(fd, 1, 15);
		}
		read(in, buf, N);
		//printf("w:\t%d\t", cnt);
		//print_buf(buf, N);
		if (etalon - total >= N) {
			total += write(fd, buf, N);
		} else {
			total += write(fd, buf, etalon - total);
		}
		if (!(cnt % 1000)) {
			printf("%lu\n", total / 1000000);
		}
	}
	close(in);
	close(fd);
	printf("Записано: %lu.\n", total);
	return 0;
errOpen:
	printf("Error! Unable to open the file!\n");
	return -1;
}
