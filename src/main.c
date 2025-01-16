#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h> // exit
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <elf.h>

void usage_error() {
	dprintf(STDERR_FILENO, "usage: ./ft_nm filename\n");
	exit(1);
}

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

void print_elf_header(Elf64_Ehdr *h) {
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

void print_section_header(const Elf64_Shdr *sht, const char *shstrtab, int i) {
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

void print_symbols(Elf64_Sym *symtab, char *strtab, int num_symbols) {
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
}

bool is_elf(Elf64_Ehdr *h) {
	if (h->e_ident[EI_MAG0] != 0x7f) return false;
	if (h->e_ident[EI_MAG1] != 'E') return false;
	if (h->e_ident[EI_MAG2] != 'L') return false;
	if (h->e_ident[EI_MAG3] != 'F') return false;
	return true;
}

bool is_64bit(Elf64_Ehdr *h) {
	if (h->e_ident[EI_CLASS] != ELFCLASS64) return false;
	return true;
}

void sort_symbols(Elf64_Sym *symtab, int num_symbols, char *strtab) {
	for (int i = 0; i < num_symbols; ++i) {
		for (int j = i + 1; j < num_symbols; ++j) {
			if (strcmp(strtab + symtab[i].st_name, strtab + symtab[j].st_name) > 0) {
				Elf64_Sym tmp = symtab[i];
				symtab[i] = symtab[j];
				symtab[j] = tmp;
			}
		}
	}
}

char get_symbol_type(const Elf64_Sym *sym, const Elf64_Shdr *shdrs) {
    unsigned char bind = ELF64_ST_BIND(sym->st_info);
    unsigned char type = ELF64_ST_TYPE(sym->st_info);
	(void)type;
	// Weak symbol
	if (bind == STB_WEAK) {
		// TODO: 'W' if a default value is specified
		return (sym->st_value != 0) ? 'W' : 'w';
	}
	const Elf64_Shdr *sec = &shdrs[sym->st_shndx];
    // Text section
    if (sec->sh_flags & SHF_EXECINSTR) {
        return (bind == STB_LOCAL) ? 't' : 'T';
    }

    // BSS
    if ((sec->sh_type == SHT_NOBITS) &&
        (sec->sh_flags & SHF_ALLOC) &&
        (sec->sh_flags & SHF_WRITE)) {
        return (bind == STB_LOCAL) ? 'b' : 'B';
    }

	// Data sections (flags: Writable and Allocated, but not Executable)
	//               (type: not NOBITS)
    if ((sec->sh_type != SHT_NOBITS) &&
        (sec->sh_flags & SHF_ALLOC) &&
        (sec->sh_flags & SHF_WRITE)) {
		return (bind == STB_LOCAL) ? 'd' : 'D';
	}
	// Read-only data sections (flags: Allocated, but not Writable nor Executable)
	if ((sec->sh_type == SHT_PROGBITS || sec->sh_type == SHT_NOTE) &&
		(sec->sh_flags & SHF_ALLOC)) {
		return (bind == STB_LOCAL) ? 'r' : 'R';
	}

    if (sym->st_shndx == SHN_UNDEF) return 'U';
    if (sym->st_shndx == SHN_ABS) return 'A';
    if (sym->st_shndx == SHN_COMMON) return 'C';

    return '?'; // Unknown type
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		usage_error();
	}
	printf("sizeof(Elf64_Ehdr): %lu\n", sizeof(Elf64_Ehdr));
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
	Elf64_Ehdr *h = (Elf64_Ehdr *)map;
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
	Elf64_Shdr *sht = (Elf64_Shdr *)(map + h->e_shoff);
	Elf64_Shdr *shstrtab_header = &sht[h->e_shstrndx];
	char *shstrtab = (char *)(map + shstrtab_header->sh_offset);
	char *strtab = NULL;
	Elf64_Shdr *symtab_header = NULL;
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
	// In order to sort the symbols, we need to read the entire symbol table
	Elf64_Sym *symtab = malloc(symtab_header->sh_size);
	if (!symtab) {
		perror("malloc");
		exit(1);
	}
	memcpy(symtab, map + symtab_header->sh_offset, symtab_header->sh_size);
	int num_symbols = symtab_header->sh_size / sizeof(Elf64_Sym);
	print_symbols(symtab, strtab, num_symbols);
	sort_symbols(symtab, num_symbols, strtab);
	for (int i = 0; i < num_symbols; ++i) {
		Elf64_Sym *sym = &symtab[i];
		if (sym->st_name == 0) continue;
		const char *name = strtab + sym->st_name;
		char type = get_symbol_type(sym, sht);
		if (type == 'A') continue; // Debugger only?
		if (sym->st_value) {
				printf("%016lx %c %s\n", sym->st_value, type, name);
		} else {
				printf("%s %c %s\n", "                ", type, name);
		}
	}
	close(fd);
	free(symtab);
	munmap(map, st.st_size);
	return 0;
}
