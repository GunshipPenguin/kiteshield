#!/usr/bin/python3
import binascii
import math
import sys

BYTES_PER_LINE = 16


def bin_to_header(bin_file, array_name):
    byte_strs = \
        ['0x' + binascii.hexlify(byte).decode('ascii')
         for byte in iter(lambda: bytes(bin_file.read(1)), b'')]

    sys.stdout.write('#ifndef KITESHIELD_%s_H\n' % array_name.upper())  
    sys.stdout.write('#define KITESHIELD_%s_H\n\n' % array_name.upper())
    sys.stdout.write('char %s[%d] = {\n' % (array_name, len(byte_strs)))

    for line_num in range(math.ceil(len(byte_strs) / BYTES_PER_LINE)):
        line_list = byte_strs[BYTES_PER_LINE*line_num:BYTES_PER_LINE*line_num+BYTES_PER_LINE]
        line_num_comment = '/* %s */' % hex(line_num * BYTES_PER_LINE)
        sys.stdout.writelines([
            line_num_comment, '  ', ', '.join(line_list), ',\n' 
        ])

    sys.stdout.write('};\n\n')
    sys.stdout.write('#endif\n')

if __name__ == '__main__':
    if len(sys.argv) == 2:
        bin_to_header(sys.stdin.buffer, sys.argv[1])
    elif len(sys.argv) == 3:
        bin_to_header(open(sys.argv[2], 'rb'), sys.argv[1])
    else:
        print(
            'Syntax: python3 bin_to_header.py <array name> [input file]',
            file=sys.stderr)

