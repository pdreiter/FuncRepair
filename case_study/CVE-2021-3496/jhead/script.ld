PHDRS
{
	headers PT_PHDR PHDRS ;
	interp PT_INTERP ;
	text PT_LOAD FILEHDR PHDRS ;
	data PT_LOAD ;
	dynamic PT_DYNAMIC ;
}

SECTIONS
{
	. = SIZEOF_HEADERS;
	.rela.plt : { *(.rela.plt) } :text
	.plt : { *(.plt) } :text
	.plt.got : { *(.plt.got) } :text
	.text : { *(.text) } :text
	.data : { *(.data) } :text
	.rodata : { *(.rodata) } :text
	.bss : { *(.bss) } :text
	.dynamic : { *(.dynamic) } :text
}
