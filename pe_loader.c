#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define success 1
#define ON_EXE

typedef int (WINAPI * EXE_TLS)();
typedef int (WINAPI * DLLMAIN)(void *, int, void *);

typedef struct {
  u8 * header;
  u32 e_lfanew
} dos_header;

typedef struct {
  u8 * header;
  u16 no_of_sections;
  u16 size_of_optional_header;
  u16 characteristics;
} pe_header;

typedef struct {
  u8 * header;
  u32 virtual_size;
  u32 virtual_address;
  u32 size_of_raw_data;
  u32 pointer_to_raw_data;
  u32 characteristics;
} section_header;

typedef struct {
  u8 * header;
  u32 import_name_table_rva;
  u32 library_name_rva;
  u32 import_address_table_rva;
} import_directory;

typedef struct {
  u8 * header;
  u32 virtual_address;
  u32 size_of_block;
} base_relocation_table;

typedef struct {
  u8 * header;
  u16 magic;
  u32 address_of_entry_point;
  size_t image_base;
  u32 size_of_image;
  u32 size_of_headers;
  u16 dll_characteristics;
  u32 import_directory_rva;
  u32 resource_directory_rva;
  u32 resource_directory_size;
  u32 exception_directory_rva;
  u32 exception_directory_size;
  u32 base_relocation_tablerva;
  u32 base_relocation_tablesize;
  u32 tls_directory_rva;
  u32 tls_directory_size;
} optional_header;

static inline void write_size_t (const u8 * dest, size_t data) {
    *(size_t *) dest = data;
}

static inline size_t read_size_t (const u8 * ptr) {
  return *(const size_t *) ptr;
}

static inline u32 read_u32 (const u8 * ptr) {
  return *(const u32 *) ptr;
}

static inline u16 read_u16 (const u8 * ptr) {
  return *(const u16 *) ptr;
}

static inline const u8 * skip (const u8 * ptr, size_t offset) {
  return ptr + offset;
}

dos_header get_dos_header (const u8 * data) {
  dos_header dosheader;

  dosheader.header = data;
  dosheader.e_lfanew = read_u32(skip(data, 0x3C));
  return dosheader;
}

pe_header get_pe_header (const dos_header dosheader) {
  pe_header peheader;

  peheader.header = skip(dosheader.header, dosheader.e_lfanew);
  peheader.no_of_sections = read_u16(skip(peheader.header, 0x06));
  peheader.size_of_optional_header = read_u16(skip(peheader.header, 0x14));
  peheader.characteristics =  read_u16(skip(peheader.header, 0x16));
  return peheader;
}

optional_header get_optional_header (const pe_header peheader) {
  optional_header optionalheader;

  u32 pe64_offset = (sizeof(size_t) > 4) ? 4 : 0;

  optionalheader.header = skip(peheader.header, 0x18);
  optionalheader.magic = read_u16(optionalheader.header);
  optionalheader.address_of_entry_point = read_u32(skip(peheader.header, 0x28));
  optionalheader.image_base = read_size_t(skip(peheader.header, 0x34) - pe64_offset);
  optionalheader.size_of_image = read_u32(skip(peheader.header, 0x50));
  optionalheader.size_of_headers = read_u32(skip(peheader.header, 0x54));
  optionalheader.dll_characteristics = read_u16(skip(peheader.header, 0x5E));
  optionalheader.import_directory_rva = read_u32(skip(peheader.header, 0x80) + 4 * pe64_offset);
  optionalheader.resource_directory_rva = read_u32(skip(peheader.header, 0x88) + 4 * pe64_offset);
  optionalheader.resource_directory_size = read_u32(skip(peheader.header, 0x8C) + 4 * pe64_offset);
  optionalheader.exception_directory_rva = read_u32(skip(peheader.header, 0x90) + 4 * pe64_offset);
  optionalheader.exception_directory_size = read_u32(skip(peheader.header, 0x94) + 4 * pe64_offset);
  optionalheader.base_relocation_tablerva = read_u32(skip(peheader.header, 0xA0) + 4 * pe64_offset);
  optionalheader.base_relocation_tablesize = read_u32(skip(peheader.header, 0xA4) + 4 * pe64_offset);
  optionalheader.tls_directory_rva = read_u32(skip(peheader.header, 0xC0) + 4 * pe64_offset);
  optionalheader.tls_directory_size = read_u32(skip(peheader.header, 0xc4) + 4 * pe64_offset);
  return optionalheader;
}

section_header get_section_header (const u8 * section_header_dir) {
  section_header sectionheader;

  sectionheader.header = section_header_dir;
  sectionheader.virtual_size = read_u32(skip(sectionheader.header, 0x08));
  sectionheader.virtual_address = read_u32(skip(sectionheader.header, 0x0C));
  sectionheader.size_of_raw_data = read_u32(skip(sectionheader.header, 0x10));
  sectionheader.pointer_to_raw_data = read_u32(skip(sectionheader.header, 0x14));
  sectionheader.characteristics = read_u32(skip(sectionheader.header, 0x24));
  return sectionheader;
}

import_directory get_import_directory (const u8 * import_header_dir) {
  import_directory importdirectory;

  importdirectory.header = import_header_dir;
  importdirectory.import_name_table_rva = read_u32(importdirectory.header);
  importdirectory.library_name_rva = read_u32(skip(importdirectory.header, 0x0C));
  importdirectory.import_address_table_rva = read_u32(skip(importdirectory.header, 0x10));
  return importdirectory;
}

base_relocation_table get_relocation_table (const u8 * reloc_header_dir) {
  base_relocation_table reloctable;

  reloctable.header = reloc_header_dir;
  reloctable.virtual_address = read_u32(reloctable.header);
  reloctable.size_of_block = read_u32(skip(reloctable.header, 0x04));
  return reloctable;
} 

u32 copy_headers(const u8 * src, const u8 * dest) {
  u32 size_of_headers = get_optional_header(get_pe_header(get_dos_header(src))).size_of_headers; 

  memcpy(dest, src, size_of_headers);
  return success;
}

u32 copy_sections (const u8 * src, const u8 * dest) {
  pe_header peheader = get_pe_header(get_dos_header(src));
  section_header sectionheader = get_section_header(skip(skip(peheader.header, 0x18), 
                                                         peheader.size_of_optional_header));

  while (peheader.no_of_sections--) {
    memcpy(skip(dest, sectionheader.virtual_address), 
           skip(src, sectionheader.pointer_to_raw_data), sectionheader.size_of_raw_data);
    
    sectionheader = get_section_header(skip(sectionheader.header, 0x28));
  }

  return success;
}

u32 resolve_imports (const u8 * src, const u8 * dest) {
  u32 import_directory_rva = get_optional_header(get_pe_header(get_dos_header(src))).import_directory_rva;

  if (!import_directory_rva) return success;

  import_directory importdirectory = get_import_directory(skip(dest, import_directory_rva));

  while (importdirectory.library_name_rva) {
    u8 * iat = skip(dest, importdirectory.import_address_table_rva);
    u8 * INT = skip(dest, importdirectory.import_name_table_rva);
    u8 * library_address = LoadLibraryA(skip(dest, importdirectory.library_name_rva));

    while (read_size_t(iat)) {
      u8 msb_set = (u8) (read_size_t(INT) >> ((sizeof(size_t) * 8) - 1) );
      u8 * func_name_ord = msb_set * read_size_t(INT) + (1 - msb_set) * 
                           (size_t) skip(skip(dest, read_size_t(INT)), 0x02);

      write_size_t(iat, GetProcAddress(library_address, func_name_ord));

      iat = iat + sizeof(size_t);
      INT = INT + sizeof(size_t);
    }
   
    importdirectory = get_import_directory(skip(importdirectory.header, 0x14));
  }

  return success;
}

u32 fix_relocations (const u8 * src, const u8 * dest) {
  optional_header optionalheader = get_optional_header(get_pe_header(get_dos_header(src)));

  intptr_t delta = (intptr_t) dest - (intptr_t) optionalheader.image_base;

  if (!optionalheader.base_relocation_tablerva) return success;

  base_relocation_table reloctable = get_relocation_table(skip(dest, optionalheader.base_relocation_tablerva));

  while (reloctable.size_of_block) {
    u8 * reloc_page = dest + reloctable.virtual_address;
    u32 reloc_entries_count = (reloctable.size_of_block - 0x08) >> 1; 
    u8 * reloc_entry = skip(reloctable.header, 0x08);

    while (reloc_entries_count--) {
      u8 entry_type = (u8) (read_u16(reloc_entry) >> 12);
      size_t * absolute_reloc_entry = (size_t *) skip(reloc_page, (read_u16(reloc_entry) & 0x0FFF) );

      *(absolute_reloc_entry) += entry_type == 10 ? delta : 0;
      *(absolute_reloc_entry) += entry_type == 3 ? (u32) delta : 0;
      *(absolute_reloc_entry) += entry_type == 1 ? ((u32) delta ) >> 16 : 0;
      *(absolute_reloc_entry) += entry_type == 2 ? ((u32) delta ) & 0xFFFF : 0;

      reloc_entry += 0x02;
    }

    reloctable = get_relocation_table(skip(reloctable.header, reloctable.size_of_block));
  }

  return success;
}

u32 set_section_protections (const u8 * src, const u8 * dest) {
  pe_header peheader = get_pe_header(get_dos_header(src));
  section_header sectionheader = get_section_header(skip(skip(peheader.header, 0x18),
                                                         peheader.size_of_optional_header));

  while (peheader.no_of_sections--) {
    u32 exec = sectionheader.characteristics & 0x20000000;
    u32 read = sectionheader.characteristics & 0x40000000;
    u32 write = sectionheader.characteristics & 0x80000000;

    u32 perms = (!exec && !read && !write) * 0x01 + 
                (!exec && !read && write) * 0x08 +
                (!exec && read && !write) * 0x02 +
                (!exec && read && write) * 0x04 +
                (exec && !read && !write) * 0x10 +
                (exec && !read && write) * 0x80 +
                (exec && read && !write) * 0x20 +
                (exec && read && write) * 0x40;

    perms |= ((sectionheader.characteristics & 0x04000000) != 0) * 0x200;

    VirtualProtect(dest + sectionheader.virtual_address, sectionheader.virtual_size, perms, &perms);
    sectionheader = get_section_header(skip(sectionheader.header, 0x28));
  }

  return success;
}

u32 execute_tls_callbacks (const u8 * src, const u8 * dest) {
  optional_header optionalheader = get_optional_header(get_pe_header(get_dos_header(src)));

  if (!optionalheader.tls_directory_rva) return success;

  u8 * tls_directory = dest + optionalheader.tls_directory_rva;
  size_t * tls_callback_entry = *(size_t *) (tls_directory + sizeof(size_t) * 3);

  while (*tls_callback_entry) {
    #ifdef ON_EXE 
      (*(EXE_TLS) tls_callback_entry)();
    #else
      (*(DLLMAIN) tls_callback_entry)(dest, 0x01, NULL);
    #endif

    tls_callback_entry += sizeof(size_t);
  }

  return success;
}

void *read_file (const char * filename) {
  FILE *file = fopen(filename, "rb");

  fseek(file, 0, SEEK_END);
  long size = ftell(file);
  rewind(file);

  void *file_buffer = malloc(size);
  size_t read_size = fread(file_buffer, 1, size, file);
  fclose(file);

  return file_buffer;
}    

int main ( ) {
  const u8 * src = read_file("file.exe");
  optional_header optionalheader = get_optional_header(get_pe_header(get_dos_header(src)));
  u16 is_PE32 = (optionalheader.magic == 0x10b);

  if (!(sizeof(size_t) == 4) && !is_PE32) return 0;

  u8 * dest = malloc(optionalheader.size_of_image);

  copy_headers(src, dest);
  copy_sections(src, dest);
  resolve_imports(src, dest);
  fix_relocations(src, dest);
  /* (is_PE32) ? hook_x86_exceptions() : register_x64_exceptions(src, dest); */
  set_section_protections(src, dest);
  execute_tls_callbacks(src, dest);
  
  u8 * entry_point = dest + optionalheader.address_of_entry_point;

  #ifdef ON_EXE 
      (*(EXE_TLS) entry_point)();
    #else
      (*(DLLMAIN) entry_point)(dest, 0x01, NULL);
    #endif

  return success;
}
