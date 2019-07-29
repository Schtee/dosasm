# Building somewhat valid COM files
Troubles so far:
* valid syntax for assembler. Found online assembler which would accept capstone output syntax. Saw it was using gcc, which afaik uses `gas` as assembler
	* found it was using `.intel_syntax noprefix` directive to make valid.
* found how to produce valid com file
	* `as --32 -o [output].o [input.s]` to generate object file
	* `ld -m elf_i386 --oformat binary -o [outexecutable] [output].o` to link to headerless binary (basically a DOS COM file)
* runs in DOSBOX!

NOW working: 64 bit build with interrupt stub
* Replacing interrupts with a hand-rolled C function
* Can just use default `as` and `gcc` calls as now generating for native arch
* Need to use custom `ld` call: `ld -lc -dynamic-linker /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./out.o ./util.o` for reasons I don't completely understand

Now working on 32 bit
How to handle segments?
Define a workspace in assembly
Set stack pointer to offset calculated from initial SS value from MZ header
Strip ss: segmented addresses to just be offsets from SP
