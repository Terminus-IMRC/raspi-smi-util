#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <errno.h>
#include <openssl/md5.h>
#include "bcm2835_smi.h"

#define SMI_DEV_DEFAULT "/dev/smi"

static bool verbose = 0;
static char *progname = NULL;

static void usage()
{
	printf("Usage: %s [-g] [-s] [-a addr] [-d device] [-v] [-h]\n", progname);
	printf("Utility of BCM2835 SMI device.\n");
	printf("\n");
	printf("  -g          Get settings from SMI and print to stdout\n");
	printf("  -s          Set settings to SMI, reading from stdin\n");
	printf("  -a addr     Set addr of SMI\n");
	printf("  -w size     Test: Write size bytes to SMI\n");
	printf("  -r size     Test: Read size bytes from SMI\n");
	printf("  -d device   SMI device name (default:%s)\n", SMI_DEV_DEFAULT);
	printf("  -v          Be verbose\n");
	printf("  -h          Print this help\n");
}

static char* xstrdup(const char *str)
{
	char *newstr = strdup(str);
	if (newstr == NULL) {
		fprintf(stderr, "%s:%d: error: Failed to duplicate string\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	return newstr;
}

static void* xmalloc(size_t size)
{
	uint8_t *p = malloc(size);
	if (p == NULL) {
		fprintf(stderr, "%s:%d: error: Failed to allocate %u bytes of memory\n", __FILE__, __LINE__, size);
		exit(EXIT_FAILURE);
	}
	return p;
}

static long xatol(const char *nptr)
{
	/* FIXME: Use strtol to support prefixes such as 0x and 0b. */
	return atol(nptr);
}

static void print_hash(const void *d, const size_t n)
{
	size_t i;
	uint8_t hash[MD5_DIGEST_LENGTH];
	MD5(d, n, hash);
	printf("Hash: ");
	for (i = 0; i < sizeof(hash); i ++)
		printf("%02x", hash[i]);
	printf("\n");
}

static void print_settings(struct smi_settings ss)
{
	printf("data_width=%d (", ss.data_width);
	switch (ss.data_width) {
		case 0:
			printf("8bit");
			break;
		case 1:
			printf("16bit");
			break;
		case 2:
			printf("9bit");
			break;
		case 3:
			printf("18bit");
			break;
		default:
			printf("unknown");
	}
	printf(")\n");
	printf("pack_data=%d\n", ss.pack_data);
	printf("read_setup_time=%d\n", ss.read_setup_time);
	printf("read_hold_time=%d\n", ss.read_hold_time);
	printf("read_pace_time=%d\n", ss.read_pace_time);
	printf("read_strobe_time=%d\n", ss.read_strobe_time);
	printf("write_setup_time=%d\n", ss.write_setup_time);
	printf("write_hold_time=%d\n", ss.write_hold_time);
	printf("write_pace_time=%d\n", ss.write_pace_time);
	printf("write_strobe_time=%d\n", ss.write_strobe_time);
	printf("dma_enable=%d\n", ss.dma_enable);
	printf("dma_passthrough_enable=%d\n", ss.dma_passthrough_enable);
	printf("dma_read_thresh=%d\n", ss.dma_read_thresh);
	printf("dma_write_thresh=%d\n", ss.dma_write_thresh);
	printf("dma_panic_read_thresh=%d\n", ss.dma_panic_read_thresh);
	printf("dma_panic_write_thresh=%d\n", ss.dma_panic_write_thresh);
}

static void get_settings(int fd)
{
	int reti;
	struct smi_settings ss;

	reti = ioctl(fd, BCM2835_SMI_IOC_GET_SETTINGS, &ss);
	if (reti == -1) {
		fprintf(stderr, "%s:%d: error: %s\n", __FILE__, __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	print_settings(ss);
}

static int get_config(const char *confname)
{
	int len, line_size = 0x1000 * sizeof(char), num;
	char *line = NULL, *line_orig = NULL;

	len = strlen(confname);
	line = line_orig = malloc(line_size);
	strncpy(line, confname, line_size);

	if (fgets(line, line_size, stdin) == NULL) {
		fprintf(stderr, "%s:%d: error: fgets returned NULL\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (strncmp(confname, line, len)) {
		fprintf(stderr, "%s:%d: error: confname \"%s\" does not match the head of the input line \"%s\"\n", __FILE__, __LINE__, confname, line);
		exit(EXIT_FAILURE);
	}

	line += len;
	if (*line != '=') {
		fprintf(stderr, "%s:%d: error: The input line has '%c' instead of '=' after confname\n", __FILE__, __LINE__, *line);
		exit(EXIT_FAILURE);
	}
	line ++;

	line = strsep(&line, " \t\n");
	num = atoi(line);

	free(line_orig);
	return num;
}

static void set_settings(int fd)
{
	int reti;
	struct smi_settings ss;

	ss.data_width = get_config("data_width");
	ss.pack_data = get_config("pack_data");
	ss.read_setup_time = get_config("read_setup_time");
	ss.read_hold_time = get_config("read_hold_time");
	ss.read_pace_time = get_config("read_pace_time");
	ss.read_strobe_time = get_config("read_strobe_time");
	ss.write_setup_time = get_config("write_setup_time");
	ss.write_hold_time = get_config("write_hold_time");
	ss.write_pace_time = get_config("write_pace_time");
	ss.write_strobe_time = get_config("write_strobe_time");
	ss.dma_enable = get_config("dma_enable");
	ss.dma_passthrough_enable = get_config("dma_passthrough_enable");
	ss.dma_read_thresh = get_config("dma_read_thresh");
	ss.dma_write_thresh = get_config("dma_write_thresh");
	ss.dma_panic_read_thresh = get_config("dma_panic_read_thresh");
	ss.dma_panic_write_thresh = get_config("dma_panic_write_thresh");

	if (verbose)
		print_settings(ss);

	reti = ioctl(fd, BCM2835_SMI_IOC_WRITE_SETTINGS, &ss);
	if (reti == -1) {
		fprintf(stderr, "%s:%d: error: %s\n", __FILE__, __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void set_addr(int fd, const char *addr_str)
{
	int reti;
	unsigned int addr;

	addr = atoi(addr_str);

	if (verbose)
		printf("%s:%d: addr = 0x%08x\n", __FILE__, __LINE__, addr);

	reti = ioctl(fd, BCM2835_SMI_IOC_ADDRESS, &addr);
	if (reti == -1) {
		fprintf(stderr, "%s:%d: error: %s\n", __FILE__, __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void test_write(const int fd, size_t size)
{
	uint8_t *p = xmalloc(size);
	double time;
	struct timeval start, end;
	ssize_t retss;

	{
		size_t i;
		if (verbose)
			printf("%s:%d: Initializing memory\n", __FILE__, __LINE__);
		for (i = 0; i < size / 4; i += 4) {
			p[i + 0] = 0x5a;
			p[i + 1] = 0xa5;
			p[i + 2] = 0xa5;
			p[i + 3] = 0x5a;
		}
		p[size - 3] = 0xa5;
		p[size - 2] = 0xa5;
		p[size - 1] = 0x5a;
	}
	print_hash(p, size);

	if (verbose)
		printf("%s:%d: Writing to SMI\n", __FILE__, __LINE__);
	gettimeofday(&start, NULL);
	retss = write(fd, p, size);
	gettimeofday(&end, NULL);
	if (retss == -1) {
		fprintf(stderr, "%s:%d: error: write: %s\n", __FILE__, __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	} else if ((size_t) retss != size) {
		fprintf(stderr, "%s:%d: error: short or extra write\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	free(p);

	time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1e-6;
	printf("Write: %g [s], %g [B/s]\n", time, size / time);
}

static void test_read(const int fd, size_t size)
{
	uint8_t *p = xmalloc(size);
	double time;
	struct timeval start, end;
	ssize_t retss;

	gettimeofday(&start, NULL);
	retss = read(fd, p, size);
	gettimeofday(&end, NULL);
	if (retss == -1) {
		fprintf(stderr, "%s:%d: error: read: %s\n", __FILE__, __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	} else if ((size_t) retss != size) {
		fprintf(stderr, "%s:%d: error: short or extra read\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	print_hash(p, size);
	free(p);

	time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) * 1e-6;
	printf("Read: %g [s], %g [B/s]\n", time, size / time);
}

int main(int argc, char *argv[])
{
	int c, fd, reti;
	char *smi_dev = NULL, *addr_str = NULL, *size_str = NULL;
	enum {
		ACTION_GET        = 1 << 0,
		ACTION_SET        = 1 << 1,
		ACTION_ADDR       = 1 << 2,
		ACTION_TEST_WRITE = 1 << 3,
		ACTION_TEST_READ  = 1 << 4
	} action = 0;

	progname = argv[0];

	while ((c = getopt(argc, argv, "d:gsa:w:r:vh")) != -1) {
		switch (c) {
			case 'd':
				smi_dev = xstrdup(optarg);
				break;
			case 'g':
				action |= ACTION_GET;
				break;
			case 's':
				action |= ACTION_SET;
				break;
			case 'a':
				action |= ACTION_ADDR;
				addr_str = xstrdup(optarg);
				break;

			case 'w':
				action |= ACTION_TEST_WRITE;
				if (size_str == NULL)
					size_str = xstrdup(optarg);
				break;

			case 'r':
				action |= ACTION_TEST_READ;
				if (size_str == NULL)
					size_str = xstrdup(optarg);
				break;

			case 'v':
				verbose = 1;
				break;

			case 'h':
			case '?':
			default:
				usage();
				exit(EXIT_SUCCESS);
		}
	}

	if (!action) {
		fprintf(stderr, "%s:%d: error: Specify at least one action\n", __FILE__, __LINE__);
		usage();
		exit(EXIT_FAILURE);
	} else if ((action & ACTION_TEST_WRITE) && (action & ACTION_TEST_READ)) {
		fprintf(stderr, "%s:%d: error: Write and read test cannot be performed at the same time\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (smi_dev == NULL)
		smi_dev = xstrdup(SMI_DEV_DEFAULT);
	if (verbose)
		printf("%s:%d: Opening %s\n", __FILE__, __LINE__, smi_dev);
	fd = open(smi_dev, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "%s:%d: error: open: %s: %s\n", __FILE__, __LINE__, smi_dev, strerror(errno));
		exit(EXIT_FAILURE);
	}
	free(smi_dev);

	if (action & ACTION_GET)
		get_settings(fd);
	if (action & ACTION_SET)
		set_settings(fd);
	if (action & ACTION_ADDR) {
		set_addr(fd, addr_str);
		free(addr_str);
	}
	if (action & ACTION_TEST_WRITE) {
		test_write(fd, xatol(size_str));
		free(size_str);
	}
	if (action & ACTION_TEST_READ) {
		test_read(fd, xatol(size_str));
		free(size_str);
	}

	reti = close(fd);
	if (reti == -1) {
		fprintf(stderr, "%s:%d: error: close: %s: %s\n", __FILE__, __LINE__, smi_dev, strerror(errno));
		exit(EXIT_FAILURE);
	}

	return 0;
}
