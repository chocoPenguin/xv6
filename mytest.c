#include "types.h"
#include "user.h"
#include "stat.h"
#include "fcntl.h"

int main() {

	int fd = open("README", O_RDWR);
	char* mmap_return;

//	mmap(0, 8192*10, 1, 2, fd, 0);
//	printf(1, "mmap(0, 8192, 1, 3, fd, 0) : %d\n\n", freemem());
//	mmap(8192*10, 8192*10, 1, 3, fd, 0);
//	printf(1, "mmap(0, 8192, 1, 3, fd, 0) : %d\n\n", freemem());
	mmap_return=(char *)mmap(0, 8192*10, 1, 2, fd, 0);
	printf(1,"mmap_return: %p, contents: %s\n",mmap_return, mmap_return);
	printf(1, "mmap(0, 8192, 1, 3, fd, 0) : %d\n\n", freemem());
	mmap_return=(char *)mmap(8192*30, 4096, 1, 2, fd, 0);
	printf(1, "mmap(0, 8192, 1, 0, fd, 0) : %d\n\n", freemem());

	printf(1,"PGFLT test\n");
	printf(1,"contents: %s\n",mmap_return);

/*
	printf(1, "MYTEST START : %d\n", freemem());

	uint a1 = mmap(0, 8192, 1, 0, fd, 0);
	printf(1, "mmap(0, 8192, 1, 0, fd, 0) : %d\n", freemem());
	munmap(a1);
	printf(1, "unmap() : %d\n", freemem());

	uint a2 = mmap(8192, 8192, 1, 1, fd, 0);
	printf(1, "mmap(8192, 8192, 1, 1, fd, 0) : %d\n", freemem());
	munmap(a2);
	printf(1, "unmap() : %d\n", freemem());

	uint a3 = mmap(8192*3, 8192, 1, 3, fd, 0);
	printf(1, "mmap(8192*2, 8192, 1, 2, fd, 0) : %d\n", freemem());
	munmap(a3);
	printf(1, "unmap() : %d\n", freemem());

	uint a4 = mmap(8192*2, 8192, 1, 2, fd, 0);
	printf(1, "mmap(8192*3, 8192, 1, 1, 3, 0) : %d\n", freemem());
	munmap(a4);
	printf(1, "unmap() : %d\n", freemem());
*/
	close(fd);
	printf(1, "mytest) CLOSE\n");
	exit();
}

