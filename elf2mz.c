/*
 * Convert an ELF "executable" file which employs H. Peter Anvin's segelf
 * relocations, into an ELKS executable.
 * Copyright (c) 2020 TK Chia
 *
 * This file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; see the file COPYING3.LIB.  If not see
 * <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef __DJGPP__
# include <libgen.h>
#endif
#include "libelf.h"

#define R_386_SEGRELATIVE 48
#define R_386_OZSEG16 80
#define R_386_OZRELSEG16 81

struct relocation_s {
  uint16_t offset;
  uint16_t segment;
} __attribute__((packed)); /* 0x4 to here */;
typedef struct relocation_s relocation_t;

struct exe_mz_header_s {
  uint16_t signature;
  uint16_t last_page_bytes;
  uint16_t number_of_pages;
  uint16_t number_of_relocation_entries;
  uint16_t number_of_header_paragraphs;
  uint16_t minimum_allocated_paragraphs;
  uint16_t maximum_allocated_paragraphs;
  uint16_t initial_ss;
  uint16_t initial_sp;
  uint16_t checksum;
  uint16_t initial_ip;
  uint16_t initial_cs;
  uint16_t relocation_offset;
  uint16_t overlay_number;
} __attribute__((packed)); /* 0x1c to here */
typedef struct exe_mz_header_s exe_mz_header_t;

#define MAX_MZ_RELOCATIONS 32
relocation_t mzrelocation[MAX_MZ_RELOCATIONS];
int num_mzrelocations = 0;

uint16_t msdos_info_data_addr = -1;
uint16_t msdos_info_data_loadaddr = -1;
uint16_t msdos_info_data_size = -1;
uint16_t msdos_info_start_ip = -1;
uint16_t msdos_info_start_cs = -1;
uint16_t msdos_info_heap_top = -1;

struct minix_reloc
{
  uint32_t vaddr;
  uint16_t symndx;
  uint16_t type;
};

#define MINIX_COMBID	((uint32_t) 0x04100301ul)
#define MINIX_SPLITID_AHISTORICAL ((uint32_t) 0x04300301ul)

#define R_SEGWORD	80

#define S_TEXT		((uint16_t) -2u)
#define S_DATA		((uint16_t) -3u)
#define S_BSS		((uint16_t) -4u)
#define S_FTEXT		((uint16_t) -5u)

static const char *me;
static bool verbose = false, tiny = false, romable = false;
static const char *file_name = NULL;
static const char *outf_name = NULL;
static char *tmp_file_name = NULL;
static uint16_t total_data = 0, chmem = 0, stack = 0, heap = 0, entry = 0,
		aout_seg = 0, text_seg = 0, ftext_seg = 0, data_seg = 0;
static int ifd = -1, ofd = -1;
static Elf *elf = NULL;
static Elf_Scn *text = NULL, *ftext = NULL, *data = NULL,
	       *bss = NULL, *symtab = NULL,
	       *rtext = NULL, *rdata = NULL, *rel_dyn = NULL;
static const Elf32_Shdr *text_sh = NULL, *ftext_sh = NULL, *data_sh = NULL,
	     *bss_sh = NULL, *symtab_sh = NULL,
	     *rtext_sh = NULL, *rdata_sh = NULL, *rel_dyn_sh = NULL;
static uint32_t text_n_rels = 0, ftext_n_rels = 0, data_n_rels = 0,
		tot_n_rels = 0;
static struct minix_reloc *mrels = NULL;

static void process_relocations (Elf_Scn *scn, const Elf32_Shdr *shdr);


static void
error_exit (void)
{
  if (elf)
    elf_end (elf);
  if (ifd != -1)
    close (ifd);
  if (ofd != -1)
    close (ofd);
  if (tmp_file_name)
    unlink (tmp_file_name);
  exit (1);
}

static void
error_1 (const char *fmt, va_list ap)
{
  fprintf (stderr, "%s: error: ", me);
  vfprintf (stderr, fmt, ap);
}

static void
error (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  error_1 (fmt, ap);
  va_end (ap);
  putc ('\n', stderr);
  error_exit ();
}

static void
error_with_errno (const char *fmt, ...)
{
  int err = errno;
  va_list ap;
  va_start (ap, fmt);
  error_1 (fmt, ap);
  va_end (ap);
  fprintf (stderr, ": %s\n", strerror (err));
  error_exit ();
}

static void
error_with_elf_msg (const char *fmt, ...)
{
  int err = elf_errno ();
  va_list ap;
  va_start (ap, fmt);
  error_1 (fmt, ap);
  va_end (ap);
  fprintf (stderr, ": %s\n", elf_errmsg (err));
  error_exit ();
}

static void
error_with_help (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  error_1 (fmt, ap);
  va_end (ap);
  fprintf (stderr,
	   "\n"
	   "\n"
	   "%s -- convert ELF file into ELKS executable\n"
	   "usage: %s [-v] [--tiny] [--aout-seg A --data-seg D] \\\n"
	   "  [--total-data T | --chmem C | [--stack S] [--heap H]]\n"
	   "options:\n"
	   "  -v              print verbose debug information\n"
	   "  --tiny          output tiny model ELKS a.out\n"
	   "  --aout-seg A    output ROMable ELKS a.out, place a.out header\n"
	   "                  in ROM at A:0\n"
	   "  --data-seg D    output ROMable ELKS a.out, place data segment\n"
	   "                  at D:0\n"
	   "  --total-data T  (deprecated) set total data segment size to T\n"
	   "  --chmem C       (deprecated) set maximum non-static data size\n"
	   "                  to C\n"
	   "  --stack S       set maximum stack size to S\n"
	   "  --heap H        set maximum heap size to H\n", me, me);
  error_exit ();
}

static void
info (const char *fmt, ...)
{
  fprintf (stderr, "%s: ", me);
  va_list ap;
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  putc ('\n', stderr);
}

#define INFO(fmt, ...)	do \
			  { \
			    if (verbose) \
			      info ((fmt), __VA_ARGS__); \
			  } \
			while (0)

static void
parm_uint16 (int argc, char **argv, uint16_t *pvalue, int *pi)
{
  char *ep;
  int i = *pi + 1;
  *pi = i;
  if (i >= argc)
    error_with_help ("expected integer argument after `%s'", argv[i - 1]);

  uintmax_t x = strtoumax(argv[i], &ep, 0);
  if (x > 0xffffu || *ep != 0)
    error_with_help ("invalid integer argument `%s'", argv[i]);

  *pvalue = x;
}

static void
parse_args (int argc, char **argv)
{

  static char infile[] = "test-new.elf";
  static char opfile[] = "test-new.exe";
  me = argv[0];
  verbose = 1;


#if 0
  int i = 1;
  bool aout_seg_given = false, data_seg_given = false;
  const char *slash;

  me = argv[0];
  if ((slash = strrchr (me, '/')) != NULL)
    me = slash + 1;

  while (i < argc)
    {
      const char *arg = argv[i];

      if (arg[0] == '-')
	{
	  if (strcmp (arg + 1, "v") == 0)
	    verbose = true;
	  else if (arg[1] == '-')
	    {
	      if (strcmp (arg + 2, "tiny") == 0)
		tiny = true;
	      else if (strcmp (arg + 2, "total-data") == 0)
		parm_uint16 (argc, argv, &total_data, &i);
	      else if (strcmp (arg + 2, "chmem") == 0)
		parm_uint16 (argc, argv, &chmem, &i);
	      else if (strcmp (arg + 2, "stack") == 0)
		parm_uint16 (argc, argv, &stack, &i);
	      else if (strcmp (arg + 2, "heap") == 0)
		parm_uint16 (argc, argv, &heap, &i);
	      else if (strcmp (arg + 2, "aout-seg") == 0)
		{
		  romable = aout_seg_given = true;
		  parm_uint16 (argc, argv, &aout_seg, &i);
		}
	      else if (strcmp (arg + 2, "data-seg") == 0)
		{
		  romable = data_seg_given = true;
		  parm_uint16 (argc, argv, &data_seg, &i);
		}
	      else
		error_with_help ("unknown option `%s'", arg);
	    }
	  else
	    error_with_help ("unknown option `%s'", arg);
	}
      else if (file_name)
	error_with_help ("multiple file names!");
      else
	file_name = arg;

      ++i;
    }

  if (!file_name)
    error_with_help ("no file specified!");

  if (aout_seg_given ^ data_seg_given)
    error_with_help ("cannot specify only --aout-seg or only --data-seg");

  if (total_data)
    {
      if (chmem)
	error_with_help ("cannot specify both --total-data and --chmem");
      if (stack)
	error_with_help ("cannot specify both --total-data and --stack");
      if (heap)
	error_with_help ("cannot specify both --total-data and --heap");
    }

  if (chmem)
    {
      if (stack)
	error_with_help ("cannot specify both --chmem and --stack");
      if (heap)
	error_with_help ("cannot specify both --chmem and --heap");
    }
#endif

  file_name = infile;
  outf_name = opfile;

}

static void
set_scn (Elf_Scn **pscn, const Elf32_Shdr **psh, Elf_Scn *scn,
	 const Elf32_Shdr *shdr, const char *nature, size_t sidx)
{
  if (*pscn)
    error ("cannot have more than one %s section!", nature);

  INFO ("ELF section %#zx -> %s section", sidx, nature);
  INFO ("\tvirt. addr. %#" PRIx32 ", size %#" PRIx32
	", file offset %#" PRIx32,
	shdr->sh_addr, shdr->sh_size, shdr->sh_offset);

  if ((uint32_t) (shdr->sh_addr + shdr->sh_size) < shdr->sh_addr)
    error ("malformed %s section: segment bounds wrap around!");

  switch (shdr->sh_type)
    {
    case SHT_PROGBITS:
    case SHT_NOBITS:
      if (shdr->sh_size > (uint32_t) 0xffffu)
	error ("%s section is too large (%#" PRIx32 " > 0xffff)",
	       shdr->sh_size);
      break;
    default:
      ;
    }

  *pscn = scn;
  *psh = shdr;
}

static bool
in_scn_p (uint32_t addr, const Elf32_Shdr *shdr)
{
  return shdr && addr >= shdr->sh_addr && addr < shdr->sh_addr + shdr->sh_size;
}

static void
check_scn_overlap (const Elf32_Shdr *shdr1, const char *nature1,
		   const Elf32_Shdr *shdr2, const char *nature2)
{
  if (! shdr1 || ! shdr2)
    return;

  if (in_scn_p (shdr1->sh_addr, shdr2)
      || in_scn_p (shdr2->sh_addr, shdr1))
    error ("%s and %s sections overlap!", nature1, nature2);
}

static void
input_for_header (void)
{
  size_t num_scns, sidx;
  Elf32_Ehdr *ehdr;

  ifd = open (file_name, O_RDONLY);
  if (ifd == -1)
    error_with_errno ("cannot open input file `%s'", file_name);

  elf = elf_begin (ifd, ELF_C_READ, NULL);
  if (! elf)
    error_with_elf_msg ("cannot open input file `%s' as ELF", file_name);

  ehdr = elf32_getehdr (elf);
  if (! ehdr)
    error_with_elf_msg ("cannot get ELF header");

  if (ehdr->e_machine != EM_386)
    error ("`%s' is not an x86 ELF file");

  if (elf_getshdrnum (elf, &num_scns) != 0)
    error_with_elf_msg ("cannot get ELF section count");

  if (num_scns < 2)
    error_with_elf_msg ("ELF input has no sections");

  for (sidx = 1; sidx < num_scns; ++sidx)
    {
      Elf_Scn *scn;
      Elf32_Shdr *shdr;
      const char *name;

      scn = elf_getscn (elf, sidx);
      if (! scn)
	error_with_elf_msg ("cannot read ELF section %#zx", sidx);

      shdr = elf32_getshdr (scn);
      if (! shdr)
	error_with_elf_msg ("cannot read ELF section %#zx header", sidx);

      switch (shdr->sh_type)
	{
	case SHT_REL:
	  name = elf_strptr (elf, ehdr->e_shstrndx, shdr->sh_name);
	  if (! name)
	    error_with_elf_msg ("cannot read ELF section %#zx name", sidx);

	  if (shdr->sh_info == 0)
	    set_scn (&rel_dyn, &rel_dyn_sh, scn, shdr, "dynamic relocations",
		     sidx);
	  /* TODO: also make use of section-specific relocation sections if
	     they are present. */

	  if (strcmp (name, ".rel.text") == 0)
	    set_scn (&rtext, &rtext_sh, scn, shdr, ".rel.text", sidx);
	  else if (strcmp (name, ".rel.data") == 0)
	    set_scn (&rdata, &rdata_sh, scn, shdr, ".rel.data", sidx);

	  break;

	case SHT_PROGBITS:
	  name = elf_strptr (elf, ehdr->e_shstrndx, shdr->sh_name);
	  if (! name)
	    error_with_elf_msg ("cannot read ELF section %#zx name", sidx);

	  if (strcmp (name, ".text") == 0)
	    set_scn (&text, &text_sh, scn, shdr, "text", sidx);
	  else if (strcmp (name, ".fartext") == 0)
	    set_scn (&ftext, &ftext_sh, scn, shdr, "far text", sidx);
	  else if (strcmp (name, ".data") == 0)
	    set_scn (&data, &data_sh, scn, shdr, "data", sidx);
	  else if (shdr->sh_size != 0 && (shdr->sh_flags & SHF_ALLOC) != 0)
	    error ("stray SHT_PROGBITS SHF_ALLOC section %#zx `%s'", sidx, name);

	  break;

	case SHT_NOBITS:
	  name = elf_strptr (elf, ehdr->e_shstrndx, shdr->sh_name);
	  if (! name)
	    error_with_elf_msg ("cannot read ELF section %#zx name", sidx);

	  if (strcmp (name, ".bss") == 0)
	    set_scn (&bss, &bss_sh, scn, shdr, "BSS", sidx);
	  else if (shdr->sh_size != 0 && (shdr->sh_flags & SHF_ALLOC) != 0)
	    error ("stray SHT_NOBITS SHF_ALLOC section %#zx `%s'", sidx, name);

	  break;

	case SHT_SYMTAB:
	  name = elf_strptr (elf, ehdr->e_shstrndx, shdr->sh_name);
	  if (! name)
	    error_with_elf_msg ("cannot read ELF section %#zx name", sidx);

	  if (strcmp (name, ".symtab") == 0)
	    set_scn (&symtab, &symtab_sh, scn, shdr, "symtab", sidx);
	  else if (shdr->sh_size != 0 && (shdr->sh_flags & SHF_ALLOC) != 0)
	    error ("stray SHT_SYMTAB SHF_ALLOC section %#zx `%s'", sidx, name);

	  break;

	default:
	  ;  /* ignore other types of sections */
	}
    }

    if (symtab) {
      Elf_Data *data = elf_getdata(symtab, NULL);
      Elf32_Sym *sym;
      int count, i;
      char *p;

      if (!data)
        error_with_elf_msg("cannot read symtab");

      if (data->d_size != symtab_sh->sh_size)
        error("short ELF read");

      count = symtab_sh->sh_size / symtab_sh->sh_entsize;
      for (i = 0; i < count; i++) {
        sym = (Elf32_Sym *)data->d_buf + i;

        p = elf_strptr(elf, symtab_sh->sh_link, sym->st_name);

        if (strcmp(p, "__msdos_info_data_addr") == 0) {
          msdos_info_data_addr = (uint16_t)sym->st_value;

	} else if (strcmp(p, "__msdos_info_data_loadaddr") == 0) {
          msdos_info_data_loadaddr = (uint16_t)sym->st_value;

        } else if (strcmp(p, "__msdos_info_data_size") == 0) {
          msdos_info_data_size = (uint16_t)sym->st_value;

        } else if (strcmp(p, "__msdos_info_start_cs") == 0) {
          msdos_info_start_cs = (uint16_t)sym->st_value;

        } else if (strcmp(p, "__msdos_info_start_ip") == 0) {
          msdos_info_start_ip = (uint16_t)sym->st_value;

        } else if (strcmp(p, "__msdos_info_heap_top") == 0) {
          msdos_info_heap_top = (uint16_t)sym->st_value;

        } else if (strncmp(p, "__msdos_info", 12) == 0) {
          printf("Name == %s, value = 0x%04x\n", p, sym->st_value);
        }
      }
    }

  if (rtext)
    process_relocations (rtext, rtext_sh);

  if (rdata)
    process_relocations (rdata, rdata_sh);

  if (! in_scn_p (ehdr->e_entry, text_sh))
    error ("entry point outside near text segment");

  entry = ehdr->e_entry - text_sh->sh_addr;

/*
  Don't need to check section overlap as section == segment

  check_scn_overlap (text_sh, "text", ftext_sh, "far text");
  check_scn_overlap (text_sh, "text", data_sh, "data");
  check_scn_overlap (text_sh, "text", bss_sh, "BSS");
  check_scn_overlap (ftext_sh, "far text", data_sh, "data");
  check_scn_overlap (ftext_sh, "far text", bss_sh, "BSS");
  check_scn_overlap (data_sh, "data", bss_sh, "BSS");
 */

/*
  if (tiny)
    {
      if (ftext)
	error ("tiny model program cannot have far text segment!");

      if (text)
	{
	  if (data
	      && text_sh->sh_addr + text_sh->sh_size != data_sh->sh_addr)
	    error ("data segment must come right after text in tiny model!");

	  if (! data && bss
	      && text_sh->sh_addr + text_sh->sh_size != bss_sh->sh_addr)
	    error ("data segment must come right after text in tiny model!");
	}
    }
  */

  if (rel_dyn)
    {
      Elf_Data *stuff = elf_getdata (rel_dyn, NULL);
      size_t stuff_size;
      const Elf32_Rel *prel;

      if (! stuff)
	error_with_elf_msg ("cannot read dynamic relocations");

      stuff_size = stuff->d_size;
      if (stuff_size != rel_dyn_sh->sh_size)
	error ("short ELF read of dynamic relocations");

      if (! stuff_size || stuff_size % sizeof (Elf32_Rel) != 0)
	error ("weirdness when reading dynamic relocations!");

      prel = (const Elf32_Rel *) stuff->d_buf;
      while (stuff_size)
	{
	  uint32_t vaddr = prel->r_offset;

	  if (in_scn_p (vaddr, text_sh))
	    {
	      ++text_n_rels;
	      if (text_n_rels > (uint32_t) 0x8000u)
		error ("too many text segment relocations");
	    }
	  else if (in_scn_p (vaddr, ftext_sh))
	    {
	      ++ftext_n_rels;
	      if (ftext_n_rels > (uint32_t) 0x8000u)
		error ("too many far text segment relocations");
	    }
	  else if (in_scn_p (vaddr, data_sh))
	    {
	      ++data_n_rels;
	      if (data_n_rels > (uint32_t) 0x8000u)
		error ("too many data segment relocations");
	    }
	  else
	    error ("stray relocation outside text and data sections!");

	  ++prel;
	  stuff_size -= sizeof (Elf32_Rel);
	}
    }

  tot_n_rels = text_n_rels + ftext_n_rels + data_n_rels;

  if (romable)
    {
      text_seg = aout_seg + 2;

      if (text && text_sh->sh_size % 0x10u != 0)
	error ("text section end not paragraph-aligned for ROMable output");

      ftext_seg = text_seg + text_sh->sh_size / 0x10u;
    }

  INFO ("%" PRIu32 " text reloc(s)., %" PRIu32 " far text reloc(s)., "
	"%" PRIu32 " data reloc(s).", text_n_rels, ftext_n_rels, data_n_rels);
}

static void
start_output (void)
{
  char *dir;
  size_t dir_len;

  tmp_file_name = malloc (strlen (file_name) + 8);
  if (! tmp_file_name)
    error_with_errno ("gut reaction %d", (int) __LINE__);

  strcpy (tmp_file_name, file_name);

  dir = dirname (tmp_file_name);
  /* Argh... */
  if (dir != tmp_file_name)
    strcpy (tmp_file_name, dir);

  dir_len = strlen (tmp_file_name);
  if (dir_len && tmp_file_name[dir_len - 1] != '/'
	      && tmp_file_name[dir_len - 1] != '\\')
    {
      tmp_file_name[dir_len] = '/';
      ++dir_len;
    }
  strcpy (tmp_file_name + dir_len, "XXXXXX");

  ofd = mkstemp (tmp_file_name);
  if (ofd == -1)
    error_with_errno ("cannot create temporary output file");

  INFO ("created temporary file `%s'", tmp_file_name);
}

static void
output (const void *buf, size_t n)
{
  ssize_t r;
  const char *p = (const char *) buf;
  while (n)
    {
      r = write (ofd, p, n);

      if (r < 0)
	error_with_errno ("cannot write output file");

      if (! r)
	error ("cannot write output file: disk full?");

      p += r;
      n -= r;
    }
}

// cycle through section looking for OZ*SEG16s
static void
process_relocations (Elf_Scn *scn, const Elf32_Shdr *shdr)
{
  Elf_Data *stuff = elf_getdata(scn, NULL);
  size_t stuff_size;
  const Elf32_Rel *prel;

  if (!stuff)
    error_with_elf_msg("cannot read scn relocations");

  stuff_size = stuff->d_size;
  if (stuff_size != shdr->sh_size)
    error("short ELF read of scn relocations");

  if (!stuff_size || stuff_size % sizeof(Elf32_Rel) != 0)
    error("weirdness when reading scn relocations!");

  prel = (const Elf32_Rel *)stuff->d_buf;
  while (stuff_size) {
    uint32_t vaddr = prel->r_offset;
    uint8_t vtype = ELF32_R_TYPE(prel->r_info);

    if (vtype == R_386_OZRELSEG16) {
      printf("type = % 4d, addr = 0x%08x : not handled yet\n", vtype, vaddr);

    } else if (vtype == R_386_OZSEG16) {
      printf("type = % 4d, addr = 0x%08x\n", vtype, vaddr);

      if (num_mzrelocations < MAX_MZ_RELOCATIONS) {
        mzrelocation[num_mzrelocations].offset = vaddr;
        mzrelocation[num_mzrelocations].segment = 0x0; // FIXME: need to get the section segment
        num_mzrelocations++;
      } else {
        printf("mzrelocations table exceeded\n");
      }
    }

    ++prel;
    stuff_size -= sizeof(Elf32_Rel);
  }
}

static int
prepare_header(char **buf, uint16_t *bufsize)
{

  uint16_t header_size;
  exe_mz_header_t *mzhdr;
  relocation_t *prel;
  int i;

  int is_msdos_v1 = 0;

  header_size = sizeof(exe_mz_header_t);
  header_size = header_size + (num_mzrelocations * sizeof(relocation_t));
  header_size = ((header_size + 15) / 16) * 16; // round up to paragraph
  if (is_msdos_v1)
    header_size = 512;

  *bufsize = header_size;
  *buf = malloc(*bufsize);
  if (! *buf)
    return 0;

  mzhdr = (exe_mz_header_t *) *buf;
  mzhdr->signature = 0x5a4d;
  mzhdr->last_page_bytes = (header_size + msdos_info_data_loadaddr + msdos_info_data_size) % 512;
  mzhdr->number_of_pages = (header_size + msdos_info_data_loadaddr + msdos_info_data_size + 511) / 512;
  mzhdr->number_of_relocation_entries = num_mzrelocations;
  mzhdr->number_of_header_paragraphs = header_size / 16;
  mzhdr->minimum_allocated_paragraphs = ((0x10000 - msdos_info_data_size - msdos_info_data_addr) / 16) - (header_size / 16);
  mzhdr->maximum_allocated_paragraphs = (is_msdos_v1) ? 0xffff : mzhdr->minimum_allocated_paragraphs;
  mzhdr->initial_ss = (msdos_info_data_loadaddr / 16) - (header_size / 16); // DS == SS
  mzhdr->initial_sp = 0;
  mzhdr->checksum = 0;
  mzhdr->initial_ip = msdos_info_start_ip + header_size;
  mzhdr->initial_cs = msdos_info_start_cs - (header_size / 16);
  mzhdr->relocation_offset = sizeof(exe_mz_header_t);
  mzhdr->overlay_number = 0;

  for (i = 0; i < num_mzrelocations; i++) {
    prel = (relocation_t *)(*buf + sizeof(exe_mz_header_t) + sizeof(relocation_t) * i);
    prel->offset = mzrelocation[i].offset + header_size;
    prel->segment = mzrelocation[i].segment - (header_size / 16);
  }

  return 1;
}

static void
output_header (void)
{
  char * mzhdr;
  uint16_t mzhdrsize;

  // HELLO
  //

  start_output ();

  if (!prepare_header (&mzhdr, &mzhdrsize))
    error ("failed to prepare header");
  output (mzhdr, mzhdrsize);
  free(mzhdr);
}


static void
output_scn_stuff (Elf_Scn *scn, const Elf32_Shdr *shdr, uint32_t rels_start,
		  uint32_t n_rels, const char *nature)
{
  Elf_Data *stuff;
  size_t stuff_size;

  if (! scn)
    return;

  stuff = elf_getdata (scn, NULL);
  if (! stuff)
    error_with_elf_msg ("cannot read %s segment contents", nature);

  stuff_size = stuff->d_size;
  if (stuff_size != shdr->sh_size)
    error ("short ELF read of %s segment", nature);

  if (! romable || ! n_rels)
    output (stuff->d_buf, stuff_size);
  else
    {
      uint32_t ri;

      uint8_t buf[stuff_size];  /* C99 */
      memcpy (buf, stuff->d_buf, stuff_size);

      for (ri = rels_start; ri != rels_start + n_rels; ++ri)
	{
	  struct minix_reloc *pmrel = &mrels[ri];
	  uint16_t value = 0, offset_in_scn;

	  switch (pmrel->symndx)
	    {
	    case S_TEXT:
	      value = text_seg;
	      break;
	    case S_FTEXT:
	      value = ftext_seg;
	      break;
	    case S_DATA:
	      value = data_seg;
	      break;
	    default:
	      error ("gut reaction %d", (int) __LINE__);
	    }

	  offset_in_scn = (uint16_t) pmrel->vaddr;
	  buf[offset_in_scn] = (uint8_t) value;
	  buf[offset_in_scn + 1] = (uint8_t) (value >> 8);
	}

      output (buf, stuff_size);
    }
}

static void
output_scns_stuff (void)
{
  output_scn_stuff (text, text_sh, 0, text_n_rels, "text");
  output_scn_stuff (ftext, ftext_sh, text_n_rels, ftext_n_rels, "far text");
  output_scn_stuff (data, data_sh, text_n_rels + ftext_n_rels, data_n_rels, "data");
}

static void
output_relocs (void)
{
  if (! romable && tot_n_rels)
    output (mrels, tot_n_rels * sizeof (struct minix_reloc));
}

static void
end_output (void)
{
  struct stat orig_stat;
  int res;

  close (ofd);
  ofd = -1;

  if (stat (file_name, &orig_stat) == 0)
    chmod (tmp_file_name, orig_stat.st_mode & ~(mode_t) S_IFMT);

  res = rename (tmp_file_name, outf_name);

  if (res != 0 && errno == EEXIST)
    {
      unlink (file_name);
      res = rename (tmp_file_name, outf_name);
    }

  if (res != 0)
    error ("cannot rename `%s' to `%s'", tmp_file_name, outf_name);
}

int
main(int argc, char **argv)
{
  parse_args (argc, argv);
  elf_version (1);
  input_for_header ();
  output_header ();
//  convert_relocs ();
//  output_scns_stuff ();
//  output_relocs ();
  end_output ();
  return 0;
}
