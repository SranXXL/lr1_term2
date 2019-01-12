#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
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
	int fd, out;
	long unsigned total = 0;
	int ret;
	int cnt = 0;
	char* buf;

	buf = (char *)calloc(N + 1, sizeof(char));
	if (buf == NULL) {
		printf("Error! Unable to allocate memory!\n");
		return -1;
	} 
	buf[N] = '\0';

	out = open(argv[1], O_WRONLY | O_CREAT);
	fd = open("/dev/lr2_term2", O_RDONLY);
	if ((out == -1) || (fd == -1)) {
		goto errOpen;
	}
	while (total != etalon) {
		++cnt;
		if (etalon - total >= N) {
			ret = read(fd, buf, N);
		} else {
			ret = read(fd, buf, etalon - total);
		}
		total += ret;		
		// printf("r:\t%d\t", cnt);
		// print_buf(buf);
		write(out, buf, ret);
		if (!(cnt % 1000)) {
			printf("%lu\n", total / 1000000);
		}
	}
	close(out);
	close(fd);
	printf("Прочтено: %lu.\n", total);
	return 0;
errOpen:
	printf("Error! Unable to open the file!\n");
	return -1;
}