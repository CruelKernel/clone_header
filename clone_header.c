#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <linux/fs.h>
#include <getopt.h>

#define BOOT_IMAGE_HEADER_V1_SIZE 1648
#define BOOT_IMAGE_HEADER_V2_SIZE 1660

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024

#define HEADER_VERSION_OFFSET (             \
	sizeof(uint8_t) * BOOT_MAGIC_SIZE + \
	8 * sizeof(uint32_t)                \
)

typedef union __attribute__((packed)) {
	uint32_t version;
	struct {
		unsigned os_patch_level:11;
		unsigned os_version:21;
	};
	struct {
		unsigned month:4;
		unsigned year:7;
		unsigned c:7;
		unsigned b:7;
		unsigned a:7;
	};
} os_version_t;

// Boot Image Header, version 2
typedef struct __attribute__((packed)) {
	uint8_t magic[BOOT_MAGIC_SIZE];
	uint32_t kernel_size;               /* size in bytes */
	uint32_t kernel_addr;               /* physical load addr */

	uint32_t ramdisk_size;              /* size in bytes */
	uint32_t ramdisk_addr;              /* physical load addr */

	uint32_t second_size;               /* size in bytes */
	uint32_t second_addr;               /* physical load addr */

	uint32_t tags_addr;                 /* physical addr for kernel tags */
	uint32_t page_size;                 /* flash page size we assume */
	uint32_t header_version;
	os_version_t os_version;
	uint8_t name[BOOT_NAME_SIZE];       /* asciiz product name */
	uint8_t cmdline[BOOT_ARGS_SIZE];
	uint32_t id[8];                     /* timestamp / checksum / sha1 / etc */
	uint8_t extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
	uint32_t recovery_dtbo_size;        /* size of recovery image */
	uint64_t recovery_dtbo_offset;      /* offset in boot image */
	uint32_t header_size;               /* size of boot image header in bytes */
	uint32_t dtb_size;                  /* size of dtb image */
	uint64_t dtb_addr;                  /* physical load address */
} boot_img_hdr_t;


static bool stop_on(bool print_errno, bool cond, const char *message, ...)
{
	if (!cond)
		return false;

	va_list args;
	va_start(args, message);
	vfprintf(stderr, message, args);
	va_end(args);
	if (print_errno)
		fprintf(stderr, ": %s", strerror(errno));
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);

	return true;
}

#define stopx(cond, ...) stop_on(false, cond, __VA_ARGS__)
#define stop(cond, ...) stop_on(true, cond, __VA_ARGS__)

static bool check_cond(bool print_errno, bool cond, const char *message, ...)
{
	if (!cond)
		return false;

	va_list args;
	va_start(args, message);
	vfprintf(stderr, message, args);
	va_end(args);
	if (print_errno)
		fprintf(stderr, ": %s", strerror(errno));
	fprintf(stderr, "\n");

	return true;
}

#define checkx(cond, ...) check_cond(false, cond, __VA_ARGS__)
#define check(cond, ...) check_cond(true, cond, __VA_ARGS__)

static inline uint32_t get_header_version(uint8_t *addr)
{
	return *(uint32_t *)(addr + HEADER_VERSION_OFFSET);
}

static boot_img_hdr_t *mmap_boot_image(const char *file, int flags)
{
	uint8_t *addr;
	uint32_t header_version;
	struct stat st;
	int mmap_flags = PROT_READ;
	size_t block_size = BOOT_IMAGE_HEADER_V2_SIZE;

	int fd = open(file, flags);
	stop(fd < 0, "open %s failed", file);

	if (flags == O_RDWR)
		mmap_flags |= PROT_WRITE;

	stop(fstat(fd, &st) < 0, "stat %s failed", file);
	stopx(!(S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) &&
	       st.st_size < BOOT_IMAGE_HEADER_V2_SIZE,
	       "%s is too small", file);
	stopx(S_ISCHR(st.st_mode), "%s is not a block device", file);

	if (S_ISBLK(st.st_mode)) {
		check(ioctl(fd, BLKGETSIZE64, &block_size) < 0,
		      "%s can't determine block device size", file);
		stopx(block_size < BOOT_IMAGE_HEADER_V2_SIZE,
		       "%s is too small", file);
	}

	addr = mmap(NULL, BOOT_IMAGE_HEADER_V2_SIZE, mmap_flags,
		    MAP_SHARED, fd, 0);
	stop(addr == MAP_FAILED, "mmap %s failed", file);
	close(fd);

	stopx(strncmp((const char *)addr, "ANDROID!", 8),
	       "%s has incorrect magic number, not an android boot image",
		file
	);

	header_version = get_header_version(addr);
	stopx(header_version > 2,
	       "%s unsupported header version (%u)",
	       file, header_version
	);

	return (boot_img_hdr_t *) addr;
}

static bool check_headers_compatible(const boot_img_hdr_t *h1,
				     const boot_img_hdr_t *h2)
{
	bool res = false;

#define ne(field) (h1->field != h2->field)
#define ne_addr(field) \
	(!((h1->field ## _addr == h2->field ## _addr) || \
	   (h1->field ## _size == h2->field ## _size == 0)))
	if (
	   !checkx(ne(header_version), "header_versions are not compatible")
	&& !checkx(ne(kernel_addr), "kernels are not compatible")
	&& !checkx(ne_addr(ramdisk), "ramdisks are not compatible")
	&& !checkx(ne_addr(second), "seconds are not compatible")
	&& !checkx(ne(tags_addr), "tags are not compatible")
	)
		res = true;
#undef ne
#undef ne_addr

	return res;
}

static void print_header_info(const boot_img_hdr_t *h)
{
	printf("header_version %u\n", h->header_version);

	printf("name %s\n", h->name);
	printf("os_version %u.%u.%u %u-%02u\n",
		h->os_version.a, h->os_version.b, h->os_version.c,
		h->os_version.year + 2000, h->os_version.month);

	printf("cmdline %s\n", h->cmdline);
	printf("extra_cmdline %s\n", h->extra_cmdline);

	printf("kernel_addr %#010x\n", h->kernel_addr);
	printf("ramdisk_addr %#010x\n", h->ramdisk_addr);
	printf("second_addr %#010x\n", h->second_addr);
	printf("tags_addr %#010x\n", h->tags_addr);
	printf("page_size %u\n", h->page_size);

	if (h->header_version > 0) {
		printf("recovery_size %u\n", h->recovery_dtbo_size);
		printf("recovery_offset %#010lx\n", h->recovery_dtbo_offset);
		if (h->header_version > 1)
			printf("dtb_addr %#010lx\n", h->dtb_addr);
	}
}

int main(int argc, char *argv[])
{
	const char *src_file, *dst_file;
	boot_img_hdr_t *src, *dst;
	int name = true, version = true, cmd = false;

	const char *opts = "nvc";

	const struct option long_opts[] = {
		{ "name",       no_argument, NULL, 'n' },
		{ "no-name",    no_argument, NULL, -'n' },
		{ "version",    no_argument, NULL, 'v' },
		{ "no-version", no_argument, NULL, -'v' },
		{ "cmd",        no_argument, NULL, 'c' },
		{ "no-cmd",     no_argument, NULL, -'c' },
		{ "help",       no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	for (;;) {
		int res = getopt_long(argc, argv, opts, long_opts, NULL);
		if (res == -1)
			break;

		switch (res) {
		case 'n':
			name = true;
			break;
		case -'n':
			name = false;
			break;
		case 'v':
			version = true;
			break;
		case -'v':
			version = false;
			break;
		case 'c':
			cmd = true;
			break;
		case -'c':
			cmd = false;
			break;
		case 'h':
			printf("Usage: %s [options] <srcimage> <dstimage>\n", argv[0]);
			printf("Options: --[no-]name (enabled), --[no-]version (enabled), --[no-]cmd\n");
			return EXIT_SUCCESS;
		case '?':
			errx(1, "Unknown option");
			break;
		default:
			abort();
		}
	}

	stopx(argc != optind + 2, "Usage: %s [options] <srcimage> <dstimage>", argv[0]);
	src_file = argv[optind];
	dst_file = argv[optind + 1];

	src = mmap_boot_image(src_file, O_RDONLY);
	dst = mmap_boot_image(dst_file, O_RDWR);

	printf("%s info:\n", src_file);
	print_header_info(src);
	puts("");
	printf("%s info:\n", dst_file);
	print_header_info(dst);
	puts("");

	stopx(!check_headers_compatible(src, dst), "images are not compatible");

	/* We don't need to update sha after these changes.
	   Only kernel, ramdisk, second, recovery_dtbo, dtb fields
	   change sha digest.
	*/

	if (name)
		memcpy(dst->name, src->name, BOOT_NAME_SIZE);
	if (version)
		dst->os_version = src->os_version;
	if (cmd) {
		memcpy(dst->cmdline, src->cmdline, BOOT_ARGS_SIZE);
		memcpy(dst->extra_cmdline, src->extra_cmdline, BOOT_EXTRA_ARGS_SIZE);
	}

	printf("boot image fields [%s%s%s] updated\n",
		name ? "name " : "",
		version ? "version " : "",
		cmd ? "cmdline extra_cmdline": "");

	munmap(src, BOOT_IMAGE_HEADER_V2_SIZE);

	check(msync(dst, BOOT_IMAGE_HEADER_V2_SIZE, MS_SYNC) < 0,
	      "msync %s failed", dst_file);
	munmap(dst, BOOT_IMAGE_HEADER_V2_SIZE);

	return EXIT_SUCCESS;
}
