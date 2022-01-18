#!/usr/bin/python3

from pathlib import Path
from sys import exit, argv


def dump_hdr(f):
    b = f.read_bytes()

    if b[0] != ord('M') or b[1] != ord('Z'):
        print("%s: is not an EXE" % str(f))
        exit(1)

    print("%s: MZ header OK!" % str(f))
    print("  Bytes in last page:                 0x%04x" % int.from_bytes(b[2:4], "little"))
    print("  Number of pages (inc last):         0x%04x" % int.from_bytes(b[4:6], "little"))
    relocs_num = int.from_bytes(b[6:8],"little");
    print("  Number of relocation entries:       0x%04x" % relocs_num)
    print("  Header size (paragraphs):           0x%04x" % int.from_bytes(b[8:10], "little"))
    print("  Min. Memory allocated (paragraphs): 0x%04x" % int.from_bytes(b[10:12], "little"))
    print("  Max. Memory allocated (paragraphs): 0x%04x" % int.from_bytes(b[12:14], "little"))
    print("  Initial Stack Segment:              0x%04x" % int.from_bytes(b[14:16], "little"))
    print("  Initial Stack Pointer:              0x%04x" % int.from_bytes(b[16:18], "little"))
    print("  Checksum (0 for none):              0x%04x" % int.from_bytes(b[18:20], "little"))
    print("  Initial Instruction Pointer:        0x%04x" % int.from_bytes(b[20:22], "little"))
    print("  Initial Code Segment:               0x%04x" % int.from_bytes(b[22:24], "little"))
    relocs_ofs = int.from_bytes(b[24:26], "little")
    print("  Offset of relocation table:         0x%04x" % relocs_ofs)

    for i in range(relocs_num):
        if i == 0:
            print("     Relocations:")
        ofs = relocs_ofs + (i * 4)
        r = b[ofs+0:ofs+4]
        print("        %04x:%04x" % (int.from_bytes(r[2:4], "little"), int.from_bytes(r[0:2], "little")))

    print("  Overlay number:                     0x%04x" % int.from_bytes(b[26:28], "little"))

if __name__ == '__main__':
    if len(argv) > 1:
        dump_hdr(Path(argv[1]))
    else:
        print("Usage: %s file.exe" % argv[0])
