#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h> // exit
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_OSABI 7
#define EI_ABIVERSION 8
#define EI_PAD 9

#define ELFCLASSNONE 0
#define ELFCLASS32 1
#define ELFCLASS64 2

void usage_error() {
	dprintf(STDERR_FILENO, "usage: ./ft_nm filename\n");
	exit(1);
}

typedef struct ELFHeader {
	uint8_t e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} ELFHeader;

#define ET_NONE 0
#define ET_REL 1
#define ET_EXEC 2
#define ET_DYN 3
#define ET_CORE 4
#define ET_LOOS 0xfe00
#define ET_HIOS 0xfeff
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

char * string_of_e_type(uint16_t e_type) {
	switch (e_type) {
		case ET_NONE: return "ET_NONE";
		case ET_REL: return "ET_REL";
		case ET_EXEC: return "ET_EXEC";
		case ET_DYN: return "ET_DYN";
		case ET_CORE: return "ET_CORE";
		case ET_LOOS: return "ET_LOOS";
		case ET_HIOS: return "ET_HIOS";
		case ET_LOPROC: return "ET_LOPROC";
		case ET_HIPROC: return "ET_HIPROC";
		default: return "Unknown";
	}
}

void print_elf_header(ELFHeader *h) {
	printf("e_ident:     ");
	for (int i = 0; i < 16; ++i) {
		printf("%02x", h->e_ident[i]);
		if (i != 15) printf(" ");
		if (i == 7) printf(" ");
	}
	printf("\n");
	printf("e_type:      0x%x (%s)\n", h->e_type, string_of_e_type(h->e_type));
	printf("e_machine:   0x%x\n", h->e_machine);
	printf("e_version:   0x%x\n", h->e_version);
	printf("e_entry:     0x%lx\n", h->e_entry);
	printf("e_phoff:     0x%lx\n", h->e_phoff);
	printf("e_shoff:     0x%lx\n", h->e_shoff);
	printf("e_flags:     0x%x\n", h->e_flags);
	printf("e_ehsize:    0x%x\n", h->e_ehsize);
	printf("e_phentsize: 0x%x\n", h->e_phentsize);
	printf("e_phnum:     0x%x\n", h->e_phnum);
	printf("e_shentsize: 0x%x\n", h->e_shentsize);
	printf("e_shnum:     0x%x\n", h->e_shnum);
	printf("e_shstrndx:  0x%x\n", h->e_shstrndx);
}

bool is_elf(ELFHeader *h) {
	if (h->e_ident[EI_MAG0] != 0x7f) return false;
	if (h->e_ident[EI_MAG1] != 'E') return false;
	if (h->e_ident[EI_MAG2] != 'L') return false;
	if (h->e_ident[EI_MAG3] != 'F') return false;
	return true;
}

bool is_64bit(ELFHeader *h) {
	if (h->e_ident[EI_CLASS] != ELFCLASS64) return false;
	return true;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		usage_error();
	}
	printf("sizeof(ELFHeader): %lu\n", sizeof(ELFHeader));
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	struct stat st;
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(1);
	}
	printf("File size: %ld\n", st.st_size);
	void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	ELFHeader *h = (ELFHeader *)map;
	print_elf_header(h);
	if (!is_elf(h)) {
		dprintf(STDERR_FILENO, "Not an ELF file\n");
		exit(1);
	}
	if (!is_64bit(h)) {
		dprintf(STDERR_FILENO, "File architecture not suported. x86_64 only\n");
		exit(1);
	}
	close(fd);
	return 0;
}
