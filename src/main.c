#include <fcntl.h>
#include <unistd.h>
#include <stdio.h> // perror, strerror, STDERR_FILENO
#include <stdlib.h> // exit
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include "libft.h"
#include "ft_printf.h"

#define DEBUG 0
#if DEBUG
#include "debug.h"
#endif

void usage_error() {
	ft_dprintf(STDERR_FILENO, "usage: ./ft_nm filename\n");
	exit(1);
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
			int cmpval = ft_strcmp(strtab + symtab[i].st_name, strtab + symtab[j].st_name);
			bool less = cmpval < 0 || (cmpval == 0 && symtab[i].st_value < symtab[j].st_value);
			if (!less) {
				Elf64_Sym tmp = symtab[i];
				symtab[i] = symtab[j];
				symtab[j] = tmp;
			}
		}
	}
}

char get_symbol_type(const Elf64_Sym *sym, const Elf64_Shdr *shdrs) {
    unsigned char bind = ELF64_ST_BIND(sym->st_info);
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
#if DEBUG
	ft_printf("File size: %ld\n", st.st_size);
#endif
	void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	Elf64_Ehdr *h = (Elf64_Ehdr *)map;
#if DEBUG
	// print ELF header
	print_elf_header(h);
#endif
	if (!is_elf(h)) {
		ft_dprintf(STDERR_FILENO, "Not an ELF file\n");
		exit(1);
	}
	if (!is_64bit(h)) {
		ft_dprintf(STDERR_FILENO, "File architecture not suported. x86_64 only\n");
		exit(1);
	}
	// print section headers
	Elf64_Shdr *sht = (Elf64_Shdr *)(map + h->e_shoff);
	Elf64_Shdr *shstrtab_header = &sht[h->e_shstrndx];
	char *shstrtab = (char *)(map + shstrtab_header->sh_offset);
	char *strtab = NULL;
	Elf64_Shdr *symtab_header = NULL;
	for (int i = 0; i < h->e_shnum; ++i) {
#if DEBUG
		print_section_header(sht, shstrtab, i);
#endif
		if (sht[i].sh_type == SHT_SYMTAB) {
			symtab_header = &sht[i];
		}
		if (sht[i].sh_type == SHT_STRTAB) {
			if (ft_strcmp(shstrtab + sht[i].sh_name, ".strtab") == 0) {
				strtab = (char *)(map + sht[i].sh_offset);
			}
		}
	}
	// Print symbol table
	if (!symtab_header) {
		ft_dprintf(STDERR_FILENO, "No symbol table found\n");
		exit(1);
	}
	// In order to sort the symbols, we need to read the entire symbol table
	Elf64_Sym *symtab = malloc(symtab_header->sh_size);
	if (!symtab) {
		perror("malloc");
		exit(1);
	}
	ft_memcpy(symtab, map + symtab_header->sh_offset, symtab_header->sh_size);
	int num_symbols = symtab_header->sh_size / sizeof(Elf64_Sym);
#if DEBUG
	print_symbols(symtab, strtab, num_symbols);
#endif
	sort_symbols(symtab, num_symbols, strtab);
	for (int i = 0; i < num_symbols; ++i) {
		Elf64_Sym *sym = &symtab[i];
		if (sym->st_name == 0) continue;
		const char *name = strtab + sym->st_name;
		char type_char = get_symbol_type(sym, sht);
		unsigned char type = ELF64_ST_TYPE(sym->st_info);
		if (type == STT_FILE) continue; // FILE symbol type is for debugging
		if (type_char != 'U' && type_char != 'w') {
				ft_printf("%016lx %c %s\n", sym->st_value, type_char, name);
		} else {
				ft_printf("%s %c %s\n", "                ", type_char, name);
		}
	}
	close(fd);
	free(symtab);
	munmap(map, st.st_size);
	return 0;
}
