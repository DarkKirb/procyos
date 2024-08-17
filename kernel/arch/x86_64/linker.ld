PHDRS
{
  headers PT_PHDR PHDRS ;
  text PT_LOAD FILEHDR PHDRS ;
  data PT_LOAD ;
  rodata PT_LOAD ;
  dynamic PT_DYNAMIC ;
}
SECTIONS {
    . = 0xFFFFFFFF80000000;
    . += SIZEOF_HEADERS;
    . = ALIGN(0x1000);
    .text ALIGN(0x1000) : {
        *(.text .text.*)
    } :text
    . = ALIGN(0x1000);
    .got ALIGN(0x1000) : {
        *(.got .got.*)
    } :data
    .data ALIGN(0x1000) : {
        *(.data .data.*)
    } :data
    .bss ALIGN(0x1000) : {
        *(.bss .bss.*)
    } :data
    . = ALIGN(0x1000);
    .rodata ALIGN(0x1000) : {
        *(.rodata .rodata.*)
    } :rodata
    . = ALIGN(0x1000);
    .dynamic ALIGN(0x1000) : {
        *(.dynamic .dynamic.*)
    } :dynamic
}