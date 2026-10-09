elf_parser: elf_parser.c
	clang -ggdb elf_parser.c -o elf_parser

rm:
	rm elf_parser

