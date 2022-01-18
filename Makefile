
all: test-std.exe

test-std.exe: test.c
	ia16-elf-gcc -Wall -mcmodel=small -o $@ $< -li86 -Wl,-Map=test-std.map

clean:
	$(RM) test-std.exe
	$(RM) test-std.map
