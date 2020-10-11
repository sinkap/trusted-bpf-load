// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2024 Google LLC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/xattr.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>
#include <limits.h>
#include <fcntl.h>

#define MAX_SIG_SIZE 1024

int main(int argc, char *argv[])
{

	// Check if the correct number of arguments is provided
 	if (argc != 3) {
		fprintf(stderr, "Usage: %s <filename1> <filename2>\n", argv[0]);
		return 1; // Exit with an error code
	}

	char *data_path = argv[1];
	char *sig_path = argv[2];
	char sig[MAX_SIG_SIZE] = {0};
	int fd, size, ret;

	if (sig_path) {
		fd = open(sig_path, O_RDONLY);
		if (fd < 0)
			return -1;

		size = read(fd, sig, MAX_SIG_SIZE);
		close(fd);
		if (size <= 0)
			return -1;
	} else {
		/* no sig_path, just write 32 bytes of zeros */
		size = 32;
	}
	ret = setxattr(data_path, "user.sig", sig, size, 0);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return 1;
	}

	return 0;
}