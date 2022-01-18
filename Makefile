
all: test-std.exe test-new.exe
	./prnhdr.py

test.o: test.c
	ia16-elf-gcc -Wall -mcmodel=small -Os -o $@ -c $<

test-std.exe: test.o
	ia16-elf-gcc -Wall -mcmodel=small -o $@ $< -T "`ia16-elf-gcc --print-file-name=dos-mssl.ld`" -li86 -Wl,-Map=test-std.map

test-new.exe: test.o elf2mz
	ia16-elf-gcc -Wall -mcmodel=small -o test-new.elf $< -T test-new.ld -li86 -Wl,-Map=test-new.map -Wl,--oformat=elf32-i386 -Wl,-r
	./elf2mz -i test-new.elf -o $@  # options not parsed yet

elf2mz: elf2mz.c
	gcc -o $@ $< -lelf

clean:
	$(RM) test-???.exe
	$(RM) test-???.map
	$(RM) test.o
	$(RM) elf2mz
