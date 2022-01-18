all: diff

diff: test-std.hdr test-vnl.hdr
	sdiff $^ || true

test.o: test.c
	ia16-elf-gcc -Wall -mcmodel=small -Os -c -o $@ $<

test-std.exe: test.o
	ia16-elf-gcc -Wall -mcmodel=small                -Wl,-Map=$*.map -o $@ $<

test-vnl.elf: test.o test-vnl.ld
	ia16-elf-gcc -Wall -mcmodel=small -T test-vnl.ld -Wl,-Map=$*.map -o $@ $<

%.exe: %.elf
	#./elf2mz # Approx with objcopy for now
	ia16-elf-objcopy --only-section .msdos_mz_hdr -I elf32-i386 -O binary $< $@
	ia16-elf-objcopy --remove-section .msdos_mz_hdr -I elf32-i386 -O binary $< $*.rst
	cat $*.rst >> $@
	$(RM) $*.rst

%.hdr: %.exe prnhdr.py
	./prnhdr.py $< > $@

clean:
	$(RM) *.o
	$(RM) test-???.elf
	$(RM) test-???.map
	$(RM) test-???.exe
	$(RM) test-???.hdr

.PHONY: diff
.PRECIOUS: test-std.exe test-vnl.exe
.SUFFIXES: .exe .elf
