#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h> // exit
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>

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

typedef struct SectionHeaderTableEntry {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
} SectionHeaderTableEntry;

typedef struct SymbolTableEntry {
	uint32_t	st_name;
	uint8_t	st_info;
	uint8_t	st_other;
	uint16_t	st_shndx;
	uint64_t	st_value;
	uint64_t	st_size;
} SymbolTableEntry;

#define ELF64_ST_BIND(i)   ((i)>>4)
#define ELF64_ST_TYPE(i)   ((i)&0xf)
#define ELF64_ST_INFO(b,t) (((b)<<4)+((t)&0xf))

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

#define SHT_NULL          0x00
#define SHT_PROGBITS      0x01
#define SHT_SYMTAB        0x02
#define SHT_STRTAB        0x03
#define SHT_RELA          0x04
#define SHT_HASH          0x05
#define SHT_DYNAMIC       0x06
#define SHT_NOTE          0x07
#define SHT_NOBITS        0x08
#define SHT_REL           0x09
#define SHT_SHLIB         0x0a
#define SHT_DYNSYM        0x0b
#define SHT_INIT_ARRAY    0x0e
#define SHT_FINI_ARRAY    0x0f
#define SHT_PREINIT_ARRAY 0x10
#define SHT_GROUP         0x11
#define SHT_SYMTAB_SHNDX  0x12
#define SHT_NUM           0x13


char * string_of_sh_type(uint32_t sh_type) {
	switch (sh_type) {
		case 0x00: return "SHT_NULL";
		case 0x01: return "SHT_PROGBITS";
		case 0x02: return "SHT_SYMTAB";
		case 0x03: return "SHT_STRTAB";
		case 0x04: return "SHT_RELA";
		case 0x05: return "SHT_HASH";
		case 0x06: return "SHT_DYNAMIC";
		case 0x07: return "SHT_NOTE";
		case 0x08: return "SHT_NOBITS";
		case 0x09: return "SHT_REL";
		case 0x0a: return "SHT_SHLIB";
		case 0x0b: return "SHT_DYNSYM";
		case 0x0e: return "SHT_INIT_ARRAY";
		case 0x0f: return "SHT_FINI_ARRAY";
		case 0x10: return "SHT_PREINIT_ARRAY";
		case 0x11: return "SHT_GROUP";
		case 0x12: return "SHT_SYMTAB_SHNDX";
		case 0x13: return "SHT_NUM";
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

void print_section_header(const SectionHeaderTableEntry *sht, const char *shstrtab, int i) {
	const char *name = shstrtab + sht[i].sh_name;
	printf("Section %d (%s)\n", i, name);
	printf("\tsh_name:      0x%x\n", sht[i].sh_name);
	printf("\tsh_type:      0x%x (%s)\n", sht[i].sh_type, string_of_sh_type(sht[i].sh_type));
	printf("\tsh_flags:     0x%lx\n", sht[i].sh_flags);
	printf("\tsh_addr:      0x%lx\n", sht[i].sh_addr);
	printf("\tsh_offset:    0x%lx\n", sht[i].sh_offset);
	printf("\tsh_size:      0x%lx\n", sht[i].sh_size);
	printf("\tsh_link:      0x%x\n", sht[i].sh_link);
	printf("\tsh_info:      0x%x\n", sht[i].sh_info);
	printf("\tsh_addralign: 0x%lx\n", sht[i].sh_addralign);
	printf("\tsh_entsize:   0x%lx\n", sht[i].sh_entsize);
	printf("\n");
}

void sort_symbols(SymbolTableEntry *symtab, int num_symbols, char *strtab) {
	for (int i = 0; i < num_symbols; ++i) {
		for (int j = i + 1; j < num_symbols; ++j) {
			if (strcmp(strtab + symtab[i].st_name, strtab + symtab[j].st_name) > 0) {
				SymbolTableEntry tmp = symtab[i];
				symtab[i] = symtab[j];
				symtab[j] = tmp;
			}
		}
	}
}

char *string_of_symbol_type(uint8_t st_info) {
	switch (ELF64_ST_TYPE(st_info)) {
		case 0: return "NOTYPE";
		case 1: return "OBJECT";
		case 2: return "FUNC";
		case 3: return "SECTION";
		case 4: return "FILE";
		case 13: return "LOPROC";
		case 15: return "HIPROC";
		default: return "Unknown";
	}
}

char *string_of_symbol_binding(uint8_t st_info) {
	switch (ELF64_ST_BIND(st_info)) {
		case 0: return "LOCAL";
		case 1: return "GLOBAL";
		case 2: return "WEAK";
		case 13: return "LOPROC";
		case 15: return "HIPROC";
		default: return "Unknown";
	}
}

#define SHN_UNDEF 0
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2

#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2
#define STB_LOPROC 13
#define STB_HIPROC 15

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_LOPROC 13
#define STT_HIPROC 15

#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4



char get_symbol_type(const SymbolTableEntry *sym, const SectionHeaderTableEntry *shdrs) {
    if (sym->st_shndx == SHN_UNDEF) return 'U';
    if (sym->st_shndx == SHN_ABS) return 'A';
    if (sym->st_shndx == SHN_COMMON) return 'C';

    unsigned char bind = ELF64_ST_BIND(sym->st_info);
    unsigned char type = ELF64_ST_TYPE(sym->st_info);
	(void)type;

    // Example: Check section type for BSS
    if (shdrs[sym->st_shndx].sh_type == SHT_NOBITS &&
        (shdrs[sym->st_shndx].sh_flags & SHF_ALLOC) &&
        (shdrs[sym->st_shndx].sh_flags & SHF_WRITE)) {
        return (bind == STB_LOCAL) ? 'b' : 'B';
    }

    // Text section
    if (shdrs[sym->st_shndx].sh_flags & SHF_EXECINSTR) {
        return (bind == STB_LOCAL) ? 't' : 'T';
    }

    // Data section
    if (shdrs[sym->st_shndx].sh_type == SHT_PROGBITS &&
        (shdrs[sym->st_shndx].sh_flags & SHF_ALLOC) &&
        (shdrs[sym->st_shndx].sh_flags & SHF_WRITE)) {
        return (bind == STB_LOCAL) ? 'd' : 'D';
    }

    return '?'; // Unknown type
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
	// print ELF header
	print_elf_header(h);
	if (!is_elf(h)) {
		dprintf(STDERR_FILENO, "Not an ELF file\n");
		exit(1);
	}
	if (!is_64bit(h)) {
		dprintf(STDERR_FILENO, "File architecture not suported. x86_64 only\n");
		exit(1);
	}
	// print section headers
	SectionHeaderTableEntry *sht = (SectionHeaderTableEntry *)(map + h->e_shoff);
	SectionHeaderTableEntry *shstrtab_header = &sht[h->e_shstrndx];
	char *shstrtab = (char *)(map + shstrtab_header->sh_offset);
	char *strtab = NULL;
	SectionHeaderTableEntry *symtab_header = NULL;
	for (int i = 0; i < h->e_shnum; ++i) {
		print_section_header(sht, shstrtab, i);
		if (sht[i].sh_type == SHT_SYMTAB) {
			symtab_header = &sht[i];
		}
		if (sht[i].sh_type == SHT_STRTAB) {
			if (strcmp(shstrtab + sht[i].sh_name, ".strtab") == 0) {
				strtab = (char *)(map + sht[i].sh_offset);
			}
		}
	}
	// Print symbol table
	if (!symtab_header) {
		dprintf(STDERR_FILENO, "No symbol table found\n");
		exit(1);
	}
	printf("Symbol table:\n");
	// In order to sort the symbols, we need to read the entire symbol table
	SymbolTableEntry *symtab = malloc(symtab_header->sh_size);
	if (!symtab) {
		perror("malloc");
		exit(1);
	}
	memcpy(symtab, map + symtab_header->sh_offset, symtab_header->sh_size);
	int num_symbols = symtab_header->sh_size / sizeof(SymbolTableEntry);
	sort_symbols(symtab, num_symbols, strtab);
	for (int i = 0; i < num_symbols; ++i) {
			printf("Symbol %d\n", i);
			printf("\tst_name: 0x%x (%s)\n", symtab[i].st_name, strtab + symtab[i].st_name);
			printf("\tst_info: 0x%x\n", symtab[i].st_info);
			printf("\tst_other: 0x%x\n", symtab[i].st_other);
			printf("\tst_shndx: 0x%x\n", symtab[i].st_shndx);
			printf("\tst_value: 0x%lx\n", symtab[i].st_value);
			printf("\tst_size: 0x%lx\n", symtab[i].st_size);
			printf("\n");
	}
	for (int i = 0; i < num_symbols; ++i) {
		SymbolTableEntry *sym = &symtab[i];
		if (sym->st_name == 0) continue;
		const char *name = strtab + sym->st_name;
		char type = get_symbol_type(sym, sht);
		if (type == 'A') continue; // Debugger only?
		if (sym->st_value) {
				printf("%016lx %c %s\n", sym->st_value, type, name);
		} else {
				printf("%s %c %s\n", "                ", type, name);
		}
		/*
		printf("Symbol %d\n", i);
		printf("\tst_name: 0x%x (%s)\n", symtab[i].st_name, strtab + symtab[i].st_name);
		printf("\tst_info: 0x%x\n", symtab[i].st_info);
		printf("\tst_other: 0x%x\n", symtab[i].st_other);
		printf("\tst_shndx: 0x%x\n", symtab[i].st_shndx);
		printf("\tst_value: 0x%lx\n", symtab[i].st_value);
		printf("\tst_size: 0x%lx\n", symtab[i].st_size);
		printf("\n");
		*/
	}
	close(fd);
	free(symtab);
	munmap(map, st.st_size);
	return 0;
}
