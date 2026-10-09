#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <inttypes.h>

#define log_error(is_ok,e_msg) \
	if (is_ok<0){ \
	   fprintf(stderr,e_msg,strerror(errno)); \
	   return errno; \
	} 

uint16_t parse_half(unsigned char* ctx,uint64_t* idx){
   uint16_t half=0;
   for(uint32_t i=0;i<2;i++) half|=ctx[(*idx)++]<<(i*8);
   return half;
}

uint32_t parse_word(unsigned char* ctx,uint64_t* idx){
   uint32_t word=0;
   for(uint32_t i=0;i<4;i++) word|=(uint32_t)ctx[(*idx)++]<<(i*8);
   return word;
}

uint64_t parse_long(unsigned char* ctx,uint64_t* idx){
   uint64_t qword=0;
   for(uint32_t i=0;i<8;i++) qword|=(uint64_t)ctx[(*idx)++]<<(i*8);
   return qword;
}

uint64_t parse_elf64hdr(Elf64_Ehdr* elf_hdr,unsigned char* ctx){
   uint64_t ctx_idx=0;
   for(uint32_t i=0;i<EI_NIDENT;i++) elf_hdr->e_ident[i]=ctx[ctx_idx++];
#define PARSE_HALF parse_half(ctx,&ctx_idx)
#define PARSE_WORD parse_word(ctx,&ctx_idx)
#define PARSE_LONG parse_long(ctx,&ctx_idx)
   elf_hdr->e_type=PARSE_HALF;
   elf_hdr->e_machine=PARSE_HALF;
   elf_hdr->e_version=PARSE_WORD;
   elf_hdr->e_entry=PARSE_LONG;
   elf_hdr->e_phoff=PARSE_LONG;
   elf_hdr->e_shoff=PARSE_LONG;
   elf_hdr->e_flags=PARSE_WORD;
   elf_hdr->e_ehsize=PARSE_HALF;
   elf_hdr->e_phentsize=PARSE_HALF;
   elf_hdr->e_phnum=PARSE_HALF;
   elf_hdr->e_shentsize=PARSE_HALF;
   elf_hdr->e_shnum=PARSE_HALF;
   elf_hdr->e_shstrndx=PARSE_HALF;
#undef PARSE_HALF
#undef PARSE_WORD
#undef PARSE_LONG
    return ctx_idx;
}

void parse_elf64phdr(Elf64_Phdr* elf_phdr,unsigned char* ctx,uint64_t* ctx_idx){
#define PARSE_HALF parse_half(ctx,ctx_idx)
#define PARSE_WORD parse_word(ctx,ctx_idx)
#define PARSE_LONG parse_long(ctx,ctx_idx)
   elf_phdr->p_type=PARSE_WORD;
   elf_phdr->p_flags=PARSE_WORD;
   elf_phdr->p_offset=PARSE_LONG;
   elf_phdr->p_vaddr=PARSE_LONG;
   elf_phdr->p_paddr=PARSE_LONG;
   elf_phdr->p_filesz=PARSE_LONG;
   elf_phdr->p_memsz=PARSE_LONG;
   elf_phdr->p_align=PARSE_LONG;
#undef PARSE_HALF
#undef PARSE_WORD
#undef PARSE_LONG
}

void dump_elf64hdr(Elf64_Ehdr elf_hdr){
   printf("ELF header:\n");
   for(uint32_t i=0;i<EI_NIDENT;i++){
	   unsigned char ch=elf_hdr.e_ident[i];
	   if(i<4){
	      printf("file identification: ");
	      if((ch>='a'&& ch<='z')||(ch>='A'&&ch<='Z')) printf("%c\n",ch);
	      else printf("0x%x\n",ch);  
	   }
	   else if(i==4){
	      printf("File class:%s\n",
		     ch==ELFCLASSNONE?"ELFCLASSNONE"
		     :ch==ELFCLASS32?"32 bit object"
		     :ch==ELFCLASS64?"64 bit object"
		     :ch==ELFCLASSNUM?"ELFCLASSNUM":"INVALID CLASS"
		     );
	   }
	   else if(i==5){
	      printf("Data encoding: %s\n",
		    ch==ELFDATANONE?"Invalid data encoding"
		    :ch==ELFDATA2LSB?"2's complement, little endian"
		    :ch==ELFDATA2MSB?"2's complement, big endian"
		    :ch==ELFDATANUM?"ELFDATANUM"
		    :"Invalid encoding");
	   }
	   else if(i==6){
              printf("File version: %d\n",ch);
           }
           else if(i==7){
	      printf("OS ABI identification: %s\n",
		    ch==ELFOSABI_NONE?"UNIX System V ABI"
		    :ch==ELFOSABI_SYSV?"Alias"
		    :ch==ELFOSABI_HPUX?"HP-UX"
		    :ch==ELFOSABI_NETBSD?"NetBSD"
		    :ch==ELFOSABI_GNU?"Object uses GNU ELF extensions"
		    :ch==ELFOSABI_LINUX?"Compatibility alias of GNU ELF extensions"
		    :ch==ELFOSABI_SOLARIS?"Sun Solaris"
		    :ch==ELFOSABI_AIX?"IBM AIX"
		    :ch==ELFOSABI_IRIX?"SGI Irix"
		    :ch==ELFOSABI_FREEBSD?"FreeBSD"
		    :ch==ELFOSABI_TRU64?"Compaq TRU64 UNIX"
		    :ch==ELFOSABI_MODESTO?"Novell Modesto."
		    :ch==ELFOSABI_OPENBSD?"OpenBSD"
		    :ch==ELFOSABI_ARM_AEABI?"ARM EABI"
		    :ch==ELFOSABI_ARM?"ARM"
		    :ch==ELFOSABI_STANDALONE?"Standalone (embedded) application"
		    :"unkwon abi");
	   }
   }
   printf("object file type:%s\n",
	   elf_hdr.e_type==ET_NONE?"No file type "
	   :elf_hdr.e_type==ET_REL?"Relocatable file"
	   :elf_hdr.e_type==ET_EXEC?"Executable file"
	   :elf_hdr.e_type==ET_DYN?"Shared object file"
	   :elf_hdr.e_type==ET_CORE?"Core file"
	   :elf_hdr.e_type==ET_NUM?"Number of defined types"
	   :elf_hdr.e_type==ET_LOOS?"OS-specific range start"
	   :elf_hdr.e_type==ET_HIOS?"OS-specific range end"
	   :elf_hdr.e_type==ET_LOPROC?"Processor-specific range start"
	   :elf_hdr.e_type==ET_HIPROC?"Processor-specific range end"
	   :"unkownm file type");
   printf("architecture: ");
   switch (elf_hdr.e_machine) {
   case EM_NONE:       printf("No machine"); break;
   case EM_M32:        printf("AT&T WE 32100"); break;
   case EM_SPARC:      printf("SUN SPARC"); break;
   case EM_386:        printf("Intel 80386"); break;
   case EM_68K:        printf("Motorola m68k"); break;
   case EM_88K:        printf("Motorola m88k"); break;
   case EM_IAMCU:      printf("Intel MCU"); break;
   case EM_860:        printf("Intel 80860"); break;
   case EM_MIPS:       printf("MIPS R3000 big-endian"); break;
   case EM_S370:       printf("IBM System/370"); break;
   case EM_MIPS_RS3_LE: printf("MIPS R3000 little-endian"); break;
   case EM_PARISC:     printf("HPPA"); break;
   case EM_VPP500:     printf("Fujitsu VPP500"); break;
   case EM_SPARC32PLUS: printf("SPARC v8plus"); break;
   case EM_960:        printf("Intel 80960"); break;
   case EM_PPC:        printf("PowerPC"); break;
   case EM_PPC64:      printf("PowerPC 64-bit"); break;
   case EM_S390:       printf("IBM S/390"); break;
   case EM_SPU:        printf("IBM SPU/SPC"); break;
   case EM_V800:       printf("NEC V800"); break;
   case EM_FR20:       printf("Fujitsu FR20"); break;
   case EM_RH32:       printf("TRW RH-32"); break;
   case EM_RCE:        printf("Motorola RCE"); break;
   case EM_ARM:        printf("ARM"); break;
   case EM_FAKE_ALPHA: printf("Digital Alpha (obsolete)"); break;
   case EM_SH:         printf("Hitachi SH"); break;
   case EM_SPARCV9:    printf("SPARC v9"); break;
   case EM_TRICORE:    printf("Siemens TriCore"); break;
   case EM_ARC:        printf("Argonaut RISC Core"); break;
   case EM_H8_300:     printf("Hitachi H8/300"); break;
   case EM_H8_300H:    printf("Hitachi H8/300H"); break;
   case EM_H8S:        printf("Hitachi H8S"); break;
   case EM_H8_500:     printf("Hitachi H8/500"); break;
   case EM_IA_64:      printf("Intel IA-64"); break;
   case EM_MIPS_X:     printf("Stanford MIPS-X"); break;
   case EM_COLDFIRE:   printf("Motorola ColdFire"); break;
   case EM_68HC12:     printf("Motorola M68HC12"); break;
   case EM_X86_64:     printf("AMD x86-64"); break;
   case EM_AVR:        printf("Atmel AVR"); break;
   case EM_OPENRISC:   printf("OpenRISC"); break;
   case EM_XTENSA:     printf("Tensilica Xtensa"); break;
   case EM_ALTERA_NIOS2: printf("Altera Nios II"); break;
   case EM_MSP430:     printf("Texas Instruments MSP430"); break;
   case EM_BLACKFIN:   printf("Analog Devices Blackfin"); break;
   case EM_AARCH64:    printf("AArch64"); break;
   case EM_RISCV:      printf("RISC-V"); break;
   case EM_BPF:        printf("Linux BPF"); break;
   case EM_CSKY:       printf("C-SKY"); break;
   case EM_LOONGARCH:  printf("LoongArch"); break;
   case EM_ALPHA:      printf("Alpha"); break;

   default:
       printf("Unknown machine (e_machine=%u)",
              (unsigned)elf_hdr.e_machine);
       break;
   }
   putchar('\n');
   printf("e_version: %d\n",elf_hdr.e_version);

   printf("Entry point virtual address:0x%lx\n",elf_hdr.e_entry);
   printf("Program header table file offset:0x%lx\n",elf_hdr.e_phoff);
   printf("Section header table file offset: 0x%lx\n",elf_hdr.e_shoff);
   printf("Processor-specific flags: %s\n",
	 elf_hdr.e_flags==EF_SPARCV9_MM?"EF_SPARCV9_MM"
	 :elf_hdr.e_flags==EF_SPARCV9_TSO?"EF_SPARCV9_TSO"
	 :elf_hdr.e_flags==EF_SPARCV9_PSO?"EF_SPARCV9_PSO"
	 :elf_hdr.e_flags==EF_SPARCV9_RMO?"EF_SPARCV9_RMO"
	 :elf_hdr.e_flags==EF_SPARC_LEDATA?"EF_SPARC_LEDATA"
	 :elf_hdr.e_flags==EF_SPARC_EXT_MASK?"EF_SPARC_EXT_MASK"
	 :elf_hdr.e_flags==EF_SPARC_32PLUS?"EF_SPARC_32PLUS"
	 :elf_hdr.e_flags==EF_SPARC_SUN_US1?"EF_SPARC_SUN_US1"
	 :elf_hdr.e_flags==EF_SPARC_HAL_R1?"EF_SPARC_HAL_R1"
	 :elf_hdr.e_flags==EF_SPARC_SUN_US3?"EF_SPARC_SUN_US3"
	 :"unknown flags");
   printf("ELF header size in bytes:%d\n",elf_hdr.e_ehsize);
   printf("Program header table entry size: %d\n",elf_hdr.e_phentsize);
   printf("Program header table entry count: %d\n",elf_hdr.e_phnum);
   printf("Section header table entry size: %d\n",elf_hdr.e_shentsize);
   printf("Section header table entry count: %d\n",elf_hdr.e_shnum);
   printf("Section header string table index: %d\n",elf_hdr.e_shstrndx);
   putchar('\n');
}

void dump_elf64phdr(Elf64_Phdr elf_phdr){
  printf("\nELF program header\n");
  printf("Segment type: %s\n",
	 elf_phdr.p_type==PT_NULL?"rogram header table entry unused"
	 :elf_phdr.p_type==PT_LOAD?"Loadable program segment"
	 :elf_phdr.p_type==PT_DYNAMIC?"Dynamic linking information"
	 :elf_phdr.p_type==PT_INTERP?"Program interpreter"
	 :elf_phdr.p_type==PT_NOTE?"Auxiliary information"
	 :elf_phdr.p_type==PT_SHLIB?"Reserved"
	 :elf_phdr.p_type==PT_PHDR?"Entry for header table itself"
	 :elf_phdr.p_type==PT_TLS?"Thread-local storage segment"
	 :elf_phdr.p_type==PT_NUM?"Number of defined types"
	 :elf_phdr.p_type==PT_LOOS?"Start of OS-specific"
	 :elf_phdr.p_type==PT_GNU_EH_FRAME?"GCC .eh_frame_hdr segment"
	 :elf_phdr.p_type==PT_GNU_STACK?"Indicates stack executability"
	 :elf_phdr.p_type==PT_GNU_RELRO?"Read-only after relocation"
	 :elf_phdr.p_type==PT_GNU_PROPERTY?"GNU property"
	 :elf_phdr.p_type==PT_GNU_SFRAME?"SFrame segment"
	 :elf_phdr.p_type==PT_LOSUNW?"PT_LOSUNW"
	 :elf_phdr.p_type==PT_SUNWBSS?"Sun Specific segment"
	 :elf_phdr.p_type==PT_SUNWSTACK?"Stack segment"
	 :elf_phdr.p_type==PT_HISUNW?"PT_HISUNW"
	 :elf_phdr.p_type==PT_HIOS?"End of OS-specific"
	 :elf_phdr.p_type==PT_LOPROC?"Start of processor-specific"
	 :elf_phdr.p_type==PT_HIPROC?"End of processor-specific"
	 :"unknown segment");

   printf("Segment flags: \n");
   if((elf_phdr.p_flags&(1<<0)&1<<0))  printf("Segment is executable\n");
   if((elf_phdr.p_flags&(1<<1))&1<<1) printf("Segment is writable\n");
   if((elf_phdr.p_flags&(1<<2))&1<<2) printf("Segment is readable\n");
   if((elf_phdr.p_flags&PF_MASKOS)&PF_MASKOS) printf("Segment is OS-specific\n");
   if((elf_phdr.p_flags&PF_MASKPROC)&PF_MASKPROC) printf("Segmjent is Processor-specific\n");
 
   printf("Segment file offset: 0x%lx\n",elf_phdr.p_offset);
   printf("Segment virtual address: 0x%lx\n",elf_phdr.p_vaddr);
   printf("Segment physical address: 0x%lx\n",elf_phdr.p_paddr);
   printf("Segment size in file: %lu\n",elf_phdr.p_filesz);
   printf("Segment size in memory: %lu\n",elf_phdr.p_memsz);
   printf("Segment alignment: %lu\n",elf_phdr.p_align);
}

void parse_elfshdr(Elf64_Shdr* elf_shdr,unsigned char* ctx,uint64_t* ctx_idx){
#define PARSE_HALF parse_half(ctx,ctx_idx)
#define PARSE_WORD parse_word(ctx,ctx_idx)
#define PARSE_LONG parse_long(ctx,ctx_idx)
   elf_shdr->sh_name=PARSE_WORD;
   elf_shdr->sh_type=PARSE_WORD;
   elf_shdr->sh_flags=PARSE_LONG;
   elf_shdr->sh_addr=PARSE_LONG;
   elf_shdr->sh_offset=PARSE_LONG;
   elf_shdr->sh_size=PARSE_LONG;
   elf_shdr->sh_link=PARSE_WORD;
   elf_shdr->sh_info=PARSE_WORD;
   elf_shdr->sh_addralign=PARSE_LONG;
   elf_shdr->sh_entsize=PARSE_LONG;
#undef PARSE_HALF
#undef PASRE_WORD
#undef PARSE_LONG
}

void dump_strw(uint32_t word){
   for(int i=0;i<4;i++){
      unsigned char ch=(unsigned char)(word&0xff);
      if(ch==0) break;
      putchar(ch);
      word>>=8;
   }
}

void dump_elf64shdr_name(const Elf64_Shdr *shdr,const unsigned char *shstrtab,size_t shstrtab_size)
{
    //printf("section name: ");

    if (shdr->sh_name >= shstrtab_size) {
        puts("<invalid name offset>");
        return;
    }

    const char *name = (const char *)(shstrtab + shdr->sh_name);
    size_t remaining = shstrtab_size - shdr->sh_name;
    /*
    if (memchr(name, '\0', remaining) == NULL) {
        puts("<unterminated name>");
        return;
    }*/
    printf("%s\n",name);
}

//ctx+eld_shdr->sh_name

void dump_elf64shdr(Elf64_Shdr elf_shdr,Elf64_Shdr* elf_shdrptr,Elf64_Ehdr elf_hdr,unsigned char* ctx){
    printf("\nsection name: ");
    Elf64_Shdr *strtab_hdr = &elf_shdrptr[elf_hdr.e_shstrndx];
    unsigned char *shstrtab = ctx + strtab_hdr->sh_offset;
    size_t shstrtab_size = (size_t)strtab_hdr->sh_size;
    dump_elf64shdr_name(&elf_shdr,shstrtab,shstrtab_size);
    //dump_strw(elf_shdr.sh_name);
    printf("section type: %s\n",
	    elf_shdr.sh_type==SHT_NULL?"Section header table entry unused"
	    :elf_shdr.sh_type==SHT_PROGBITS?"Program data"
	    :elf_shdr.sh_type==SHT_SYMTAB?"Symbol table"
	    :elf_shdr.sh_type==SHT_STRTAB?"String table"
	    :elf_shdr.sh_type==SHT_RELA?"Relocation entries with addends"
	    :elf_shdr.sh_type==SHT_HASH?"Symbol hash table"
	    :elf_shdr.sh_type==SHT_DYNAMIC?"Dynamic linking information"
	    :elf_shdr.sh_type==SHT_NOTE?"Notes"
	    :elf_shdr.sh_type==SHT_NOBITS?"Program space with no data (bss)"
	    :elf_shdr.sh_type==SHT_REL?"Relocation entries, no addends"
	    :elf_shdr.sh_type==SHT_SHLIB?"Reserved"
	    :elf_shdr.sh_type==SHT_DYNSYM?"Dynamic linker symbol table"
	    :elf_shdr.sh_type==SHT_INIT_ARRAY?"Array of constructors"
	    :elf_shdr.sh_type==SHT_FINI_ARRAY?"Array of destructors"
	    :elf_shdr.sh_type==SHT_PREINIT_ARRAY?"Array of pre-constructors"
	    :elf_shdr.sh_type==SHT_GROUP?"Section group"
	    :elf_shdr.sh_type==SHT_SYMTAB_SHNDX?"Extended section indices"
	    :elf_shdr.sh_type==SHT_RELR?"RELR relative relocations"
	    :elf_shdr.sh_type==SHT_NUM?"Number of defined types"
	    :elf_shdr.sh_type==SHT_LOOS?"Start OS-specific"
	    :elf_shdr.sh_type== SHT_GNU_ATTRIBUTES?"Object attributes"
	    :elf_shdr.sh_type==SHT_GNU_HASH?"GNU-style hash table"
	    :elf_shdr.sh_type==SHT_GNU_LIBLIST?"Prelink library list"
	    :elf_shdr.sh_type==SHT_CHECKSUM?"Checksum for DSO content"
	    :elf_shdr.sh_type==SHT_LOSUNW?"Sun-specific low bound"
	    :elf_shdr.sh_type==SHT_SUNW_move?"SHT_SUNW_move"
	    :elf_shdr.sh_type==SHT_SUNW_COMDAT?"SHT_SUNW_COMDAT"
	    :elf_shdr.sh_type==SHT_SUNW_syminfo?"SHT_SUNW_syminfo"
	    :elf_shdr.sh_type==SHT_GNU_verdef?"Version definition section"
	    :elf_shdr.sh_type==SHT_GNU_verneed?"Version needs section"
	    :elf_shdr.sh_type==SHT_GNU_versym?"Version symbol table"
	    :elf_shdr.sh_type==SHT_HISUNW?"Sun-specific high bound"
	    :elf_shdr.sh_type==SHT_HIOS?"End OS-specific type"
	    :elf_shdr.sh_type==SHT_LOPROC?"Start of processor-specific"
	    :elf_shdr.sh_type==SHT_HIPROC?"End of processor-specific"
	    :elf_shdr.sh_type==SHT_LOUSER?"Start of application-specific"
	    :elf_shdr.sh_type==SHT_HIUSER?"End of application-specific"
	    :"invalid section type");
    printf("section flags:\n");
#define print_flag(flag,msg) if((elf_shdr.sh_flags&flag)&flag) printf(msg)
    print_flag(SHF_WRITE,"Writable\n");
    print_flag(SHF_ALLOC,"Occupies memory during execution\n");
    print_flag(SHF_EXECINSTR,"Executable\n");
    print_flag(SHF_MERGE,"Might be merged\n");
    print_flag(SHF_INFO_LINK,"`sh_info' contains SHT index\n");
    print_flag(SHF_LINK_ORDER,"Preserve order after combining\n");
    print_flag(SHF_OS_NONCONFORMING,"Non-standard OS specific handling\n");
    print_flag(SHF_GROUP,"Section is member of a group\n");
    print_flag(SHF_TLS,"Section hold thread-local data\n");
    print_flag(SHF_COMPRESSED,"Section with compressed data\n");
    print_flag(SHF_MASKOS," OS-specific\n");
    print_flag(SHF_MASKPROC,"Processor-specific\n");
    print_flag(SHF_GNU_RETAIN,"Not to be GCed by linker\n");
    print_flag(SHF_ORDERED,"Special ordering requirement\n");
    print_flag(SHF_EXCLUDE,"Section is excluded unless referenced or allocated (Solaris)\n");
#undef print_flag
    printf("Section virtual addr at execution: 0x%lx\n",elf_shdr.sh_addr);
    printf("Section file offset: 0x%lx\n",elf_shdr.sh_offset);
    printf("Section size in bytes: 0x%lx\n",elf_shdr.sh_size);
    printf("Link to another section: 0x%x\n",elf_shdr.sh_link);
    printf("Additional section information: 0x%x\n",elf_shdr.sh_info);
    printf("Section alignment: 0x%lx\n",elf_shdr.sh_addralign);
    printf("Entry size if section holds table: 0x%lx\n",elf_shdr.sh_entsize);
}

unsigned char** get_segment(Elf64_Ehdr elf_hdr,Elf64_Shdr* elf_shdr,unsigned char* ctx){
   unsigned long long segment_arr_cap=1024*1024;
   unsigned long long segment_arr_size=0;
   unsigned char** segment_arr=calloc(elf_hdr.e_shnum,sizeof(unsigned char*));

   for (uint16_t i=0;i<elf_hdr.e_shnum;++i){
    printf("segment\n");
    Elf64_Shdr *strtab_hdr = &elf_shdr[elf_hdr.e_shstrndx];
    unsigned char *shstrtab = ctx + strtab_hdr->sh_offset;
    size_t shstrtab_size = (size_t)strtab_hdr->sh_size;
    unsigned long segment_pos=0;
    unsigned long long segment_cap=1024*1024;
    segment_arr[i]=calloc(segment_cap,sizeof(unsigned char));
    const char *name = (const char *)(shstrtab + elf_shdr[i].sh_name);
    puts(name);
    while(*name){
       unsigned char ch=*name;
       segment_arr[i][segment_pos++]=ch;
       name++;
    }
    unsigned int offset=elf_shdr[i].sh_offset;
    const unsigned char* segment=ctx+offset;
    unsigned int  segment_limit=elf_shdr[i].sh_size+offset;
    while(offset<segment_limit){
       unsigned char ch=*segment;
       if(segment_pos>=segment_cap){
          segment_arr_cap*=2;
          segment_arr[i]=realloc(segment_arr[i],segment_arr_cap);
       }
       segment_arr[i][segment_pos++]=ch;
       if((ch>='0'&&ch<='9')||(ch=='a'&&ch=='z')||(ch=='A'&&ch=='Z')){
          putchar(ch);
       }
       else if(ch>=32&&ch<=125) putchar(ch);
       else{
          printf("0x%02x ",ch);
       }
       segment++; offset++;
    }
    offset=elf_shdr[i].sh_offset;
    segment=ctx+offset;

    printf("\n");
   }
   return segment_arr;
}

int32_t main(int32_t argc,char* argv[]){
   if(argc<2){
      fprintf(stderr,"you should give on eexecutable argumemnt\n");
      return -1;
   }
   char* path=argv[1];
   FILE* fptr=fopen(path,"rb");
   if(fptr==NULL){
      fprintf(stderr,"FOPEN::ERROR;%s\n",strerror(errno));
      return errno;
   }
   int32_t is_ok=fseek(fptr,0,SEEK_END);
   log_error(is_ok,"FSEEK::ERROR:%s\n");
   int64_t filesize=ftell(fptr);
   log_error(filesize,"FTELL::ERROR:%s\n");
   rewind(fptr);
   unsigned char* ctx=calloc(filesize,sizeof(unsigned char));
   if(ctx==NULL){
     fclose(fptr);
     fprintf(stderr,"CALLOC::ERROR:%s\n",strerror(errno));
     return errno;
   }
   int64_t read_size=fread(ctx,sizeof(unsigned char),filesize,fptr);
   if(read_size!=filesize){
      fprintf(stderr,"FREAD::ERROR:\n");
      return -1;
   }
   Elf64_Ehdr elf_hdr;
   uint64_t ctx_idx=parse_elf64hdr(&elf_hdr,ctx);
   dump_elf64hdr(elf_hdr);
   Elf64_Phdr* elf_phdr=calloc(elf_hdr.e_phnum,sizeof(Elf64_Phdr));
   Elf64_Shdr* elf_shdr=calloc(elf_hdr.e_shnum,sizeof(Elf64_Shdr));
   uint64_t phdr_idx=elf_hdr.e_phoff;
   for (uint16_t i = 0; i < elf_hdr.e_phnum; ++i) parse_elf64phdr(&elf_phdr[i],ctx,&phdr_idx);
   for (uint16_t i = 0; i < elf_hdr.e_phnum; ++i) dump_elf64phdr(elf_phdr[i]);
   uint64_t shdr_idx=elf_hdr.e_shoff;
   for (uint16_t i = 0; i < elf_hdr.e_shnum; ++i) parse_elfshdr(&elf_shdr[i],ctx,&shdr_idx);
   for (uint16_t i = 0; i < elf_hdr.e_shnum; ++i) dump_elf64shdr(elf_shdr[i],elf_shdr,elf_hdr,ctx);
   unsigned long long segment_arr_cap=1024*1024;
   unsigned long long segment_arr_size=0;
   unsigned char** segment_arr=calloc(elf_hdr.e_shnum,sizeof(unsigned char*));

   for (uint16_t i=0;i<elf_hdr.e_shnum;++i){
    printf("segment\n");
    Elf64_Shdr *strtab_hdr = &elf_shdr[elf_hdr.e_shstrndx];
    unsigned char *shstrtab = ctx + strtab_hdr->sh_offset;
    size_t shstrtab_size = (size_t)strtab_hdr->sh_size;
    unsigned long segment_pos=0;
    unsigned long long segment_cap=1024*1024;
    segment_arr[i]=calloc(segment_cap,sizeof(unsigned char));
    const char *name = (const char *)(shstrtab + elf_shdr[i].sh_name);
    puts(name);
    while(*name){
       unsigned char ch=*name;
       segment_arr[i][segment_pos++]=ch;
       name++;
    }
    unsigned int offset=elf_shdr[i].sh_offset;
    const unsigned char* segment=ctx+offset;
    unsigned int  segment_limit=elf_shdr[i].sh_size+offset;
    while(offset<segment_limit){
       unsigned char ch=*segment;
       if(segment_pos>=segment_cap){
          segment_arr_cap*=2;
	  segment_arr[i]=realloc(segment_arr[i],segment_arr_cap);
       }
       segment_arr[i][segment_pos++]=ch;
       if((ch>='0'&&ch<='9')||(ch=='a'&&ch=='z')||(ch=='A'&&ch=='Z')){
          putchar(ch);
       }
       else if(ch>=32&&ch<=125) putchar(ch);
       else{
          printf("0x%02x ",ch);
       }
       segment++; offset++;
    }
    offset=elf_shdr[i].sh_offset;
    segment=ctx+offset;
    
    printf("\n");
   } 
   //for()
      //for(uint64_t i=main;i<p_vaddr <= e_entry && main< p_vaddr + p_memsz)
   free(segment_arr);
   free(elf_phdr);
   free(elf_shdr);
   free(ctx);
   fclose(fptr);
}
