#include "ft_printf.h"
#include "libft.h"
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>  // perror, strerror, STDERR_FILENO
#include <stdlib.h> // exit
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEBUG 0
#if DEBUG
#include "debug.h"
#endif

// These variables are declared as global to make it easier for checking
// boundary
static struct stat st;
static void *map;

// Boundary check macros
#define CHECK_OFFSET_SIZE(offset, size, msg)                                   \
  if ((__off_t)(offset + size) > st.st_size) {                                 \
    ft_dprintf(STDERR_FILENO, "%s\n", msg);                                    \
    exit(1);                                                                   \
  }

#define CHECK_SIZE(size, msg)                                                  \
  if ((__off_t)(size) > st.st_size) {                                          \
    ft_dprintf(STDERR_FILENO, "%s\n", msg);                                    \
    exit(1);                                                                   \
  }

#define CHECK_BOUNDARY(ptr, index, entsize)                                    \
  if ((__off_t)(((void *)ptr - (void *)map) + (index + 1) * entsize) >         \
      st.st_size) {                                                            \
    ft_dprintf(STDERR_FILENO, "CHECK_BOUNDARY failed: %s %s %s\n", #ptr,       \
               #index, #entsize);                                              \
    exit(1);                                                                   \
  }

#define CHECK_CSTRING_BOUNDARY(str)                                            \
  {                                                                            \
    const char *tmp = str;                                                     \
    while (*tmp && (__off_t)((void *)tmp - (void *)map) < st.st_size) {        \
      ++tmp;                                                                   \
    }                                                                          \
    if ((__off_t)(void *)((void *)tmp - (void *)map) >= st.st_size) {          \
      ft_dprintf(STDERR_FILENO, "CHECK_CSTRING_BOUNDARY failed: %s\n", #str);  \
      exit(1);                                                                 \
    }                                                                          \
  }

void usage_error() {
  ft_dprintf(STDERR_FILENO, "usage: ./ft_nm filename\n");
  exit(1);
}

bool is_elf(Elf64_Ehdr *h) {
  if (h->e_ident[EI_MAG0] != 0x7f)
    return false;
  if (h->e_ident[EI_MAG1] != 'E')
    return false;
  if (h->e_ident[EI_MAG2] != 'L')
    return false;
  if (h->e_ident[EI_MAG3] != 'F')
    return false;
  return true;
}

bool is_64bit(Elf64_Ehdr *h) {
  if (h->e_ident[EI_CLASS] != ELFCLASS64)
    return false;
  return true;
}

// Apparently, the nm command at school is ignoring the underscore when
// comparing strings ➜  ft_nm git:(main) ✗ nm --version GNU nm (GNU Binutils for
// Ubuntu) 2.38 Copyright (C) 2022 Free Software Foundation, Inc. This program
// is free software; you may redistribute it under the terms of the GNU General
// Public License version 3 or (at your option) any later version. This program
// has absolutely no warranty. ➜  ft_nm git:(main) ✗ uname -a Linux
// c4r3s13.42tokyo.jp 6.8.0-51-generic #52~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC
// Mon Dec  9 15:00:52 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
int bsd_stricmp(const char *s1, const char *s2) {
  while (*s1 || *s2) {
    while (*s1 == '_')
      s1++;
    while (*s2 == '_')
      s2++;
    if (ft_tolower(*s1) != ft_tolower(*s2)) {
      return ft_tolower(*(unsigned char *)s1) -
             ft_tolower(*(unsigned char *)s2);
    }
    s1++;
    s2++;
  }
  return 0;
}

void sort_symbols(Elf64_Sym *symtab, int num_symbols, char *strtab) {
  for (int i = 0; i < num_symbols; ++i) {
    // Check if the symbol name is within bounds
    CHECK_CSTRING_BOUNDARY(strtab + symtab[i].st_name);
    for (int j = i + 1; j < num_symbols; ++j) {
      // Check if the symbol name is within bounds
      CHECK_CSTRING_BOUNDARY(strtab + symtab[j].st_name);
      int cmpval =
          bsd_stricmp(strtab + symtab[i].st_name, strtab + symtab[j].st_name);
      bool less = cmpval < 0 ||
                  (cmpval == 0 && symtab[i].st_value < symtab[j].st_value);
      if (!less) {
        Elf64_Sym tmp = symtab[i];
        symtab[i] = symtab[j];
        symtab[j] = tmp;
      }
    }
  }
}

char get_symbol_type(const Elf64_Sym *sym, const Elf64_Shdr *shdrs,
                     int num_sections) {
  unsigned char bind = ELF64_ST_BIND(sym->st_info);
  // Weak symbol
  if (bind == STB_WEAK) {
    // TODO: 'W' if a default value is specified
    return (sym->st_value != 0) ? 'W' : 'w';
  }
  if (sym->st_shndx == SHN_UNDEF)
    return 'U';
  if (sym->st_shndx == SHN_ABS)
    return 'A';
  if (sym->st_shndx == SHN_COMMON)
    return 'C';
  if (sym->st_shndx >= SHN_LORESERVE)
    return '?'; // TODO: Unknown type for now

  // Check if section index is within bounds
  if (sym->st_shndx >= num_sections) {
    ft_dprintf(STDERR_FILENO, "Invalid section index: %u\n", sym->st_shndx);
    return '?'; // Return unknown type if out of bounds
  }

  const Elf64_Shdr *sec = &shdrs[sym->st_shndx];
  // Text section
  if (sec->sh_flags & SHF_EXECINSTR) {
    return (bind == STB_LOCAL) ? 't' : 'T';
  }

  // BSS
  if ((sec->sh_type == SHT_NOBITS) && (sec->sh_flags & SHF_ALLOC) &&
      (sec->sh_flags & SHF_WRITE)) {
    return (bind == STB_LOCAL) ? 'b' : 'B';
  }

  // Data sections (flags: Writable and Allocated, but not Executable)
  //               (type: not NOBITS)
  if ((sec->sh_type != SHT_NOBITS) && (sec->sh_flags & SHF_ALLOC) &&
      (sec->sh_flags & SHF_WRITE)) {
    return (bind == STB_LOCAL) ? 'd' : 'D';
  }
  // Read-only data sections (flags: Allocated, but not Writable nor Executable)
  if ((sec->sh_type == SHT_PROGBITS || sec->sh_type == SHT_NOTE) &&
      (sec->sh_flags & SHF_ALLOC)) {
    return (bind == STB_LOCAL) ? 'r' : 'R';
  }

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
  if (fstat(fd, &st) < 0) {
    perror("fstat");
    exit(1);
  }
#if DEBUG
  ft_printf("File size: %ld\n", st.st_size);
#endif
  if (st.st_size < (__off_t)sizeof(Elf64_Ehdr)) {
    ft_dprintf(STDERR_FILENO, "File too small to be an ELF file\n");
    exit(1);
  }
  map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (map == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }
  // Check if we can safely read the ELF header
  CHECK_SIZE(sizeof(Elf64_Ehdr), "File too small for ELF header");
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
  if (sizeof(Elf64_Shdr) != h->e_shentsize) {
    ft_dprintf(STDERR_FILENO, "Invalid section header size\n");
    exit(1);
  }
  // Check if section header table is within bounds
  CHECK_OFFSET_SIZE(h->e_shoff, h->e_shnum * h->e_shentsize,
                    "Section header table extends beyond file");
  Elf64_Shdr *sht = (Elf64_Shdr *)(map + h->e_shoff);
  CHECK_BOUNDARY(sht, h->e_shstrndx, h->e_shentsize);
  Elf64_Shdr *shstrtab_header = &sht[h->e_shstrndx];
  // Check if section string table is within bounds
  CHECK_OFFSET_SIZE(shstrtab_header->sh_offset, shstrtab_header->sh_size,
                    "Section string table extends beyond file");
  char *shstrtab = (char *)(map + shstrtab_header->sh_offset);
  char *strtab = NULL;
  Elf64_Shdr *symtab_header = NULL;
  for (int i = 0; i < h->e_shnum; ++i) {
    CHECK_BOUNDARY(sht, i, h->e_shentsize);
    Elf64_Shdr *current_shdr = &sht[i];
#if DEBUG
    print_section_header(sht, shstrtab, i);
#endif
    if (current_shdr->sh_type == SHT_SYMTAB) {
      symtab_header = current_shdr;
      // Check if symbol table is within bounds
      CHECK_OFFSET_SIZE(symtab_header->sh_offset, symtab_header->sh_size,
                        "Symbol table extends beyond file");
    }
    if (current_shdr->sh_type == SHT_STRTAB) {
      CHECK_CSTRING_BOUNDARY(shstrtab + current_shdr->sh_name);
      if (ft_strcmp(shstrtab + current_shdr->sh_name, ".strtab") == 0) {
        strtab = (char *)(map + current_shdr->sh_offset);
        // Check if string table is within bounds
        CHECK_OFFSET_SIZE(current_shdr->sh_offset, current_shdr->sh_size,
                          "String table extends beyond file");
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
    if (sym->st_name == 0)
      continue;
    // Check if symbol name is within string table bounds
    if (sym->st_name >= symtab_header->sh_size) {
      ft_dprintf(STDERR_FILENO,
                 "Symbol name offset extends beyond string table\n");
      exit(1);
    }
    const char *name = strtab + sym->st_name;
    CHECK_CSTRING_BOUNDARY(name);
    char type_char = get_symbol_type(sym, sht, h->e_shnum);
    unsigned char type = ELF64_ST_TYPE(sym->st_info);
    if (type == STT_FILE)
      continue; // FILE symbol type is for debugging
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
