SECTIONS
{
  .rela.plt : { *(.rela.plt) }
  .plt : { *(.plt) }
  .plt.got : { *(.plt.got) }
  .text : { *(.text) }
  .data : { *(.data) }
  .rodata : { *(.rodata) }
  .bss : { *(.bss) }
  .dynamic : { *(.dynamic) }
  .dynamic : { *(.dynamic) }
  .tdata : { *(.tdata) }
}
