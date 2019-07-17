# Building somewhat valid COM files
Troubles so far:
* valid syntax for assembler. Found online assembler which would accept capstone output syntax. Saw it was using gcc, which afaik uses `gas` as assembler
	* found it was using `.intel_syntax noprefix` directive to make valid.
* found how to produce valid com file
	* `as --32 -o [output].o [input.s]` to generate object file
	* `ld -m elf_i386 --oformat binary -o [outexecutable] [output].o` to link to headerless binary (basically a DOS COM file)
* runs in DOSBOX!
