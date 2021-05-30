#!/usr/bin/python3

# String obfuscation script, this ensures that no strings exist in the loader
# code that could be useful to a reverse engineer. All potentially useful
# strings should be declared in the STRINGS map and deobfuscated at runtime
# using the DEOBF_STR macro.

import binascii
import sys

STRINGS = {
        # loader/include/anti_debug.h
        'PROC_STATUS_FMT' : '/proc/%d/status',
        'TRACERPID_PROC_FIELD': 'TracerPid:',

        # loader/runtime.c
        'PROC_STAT_FMT' : '/proc/%d/status',

        # loader/anti_debug.c
        'LD_PRELOAD' : 'LD_PRELOAD',
        'LD_AUDIT' : 'LD_AUDIT',
        'LD_DEBUG' : 'LD_DEBUG',

        # loader/string.c
        'HEX_DIGITS': '0123456789abcdef'
}

# For some reason, gcc likes to optimize out this entire statement expression
# when compiling with more than -O0, mark the cleartext array volatile to
# circumvent
_DEOBF_MACRO = '''
#define DEOBF_STR(str)                                                         \\
  ({ volatile char cleartext[sizeof(str)];                                     \\
     for (int i = 0; i < sizeof(str); i++) {                                   \\
       cleartext[i] = str[i] ^ ((0x83 + i) % 256);                             \\
     };                                                                        \\
     cleartext[sizeof(cleartext) - 1] = '\\0';                                 \\
     (char *) cleartext; })

'''

def escape_str(s):
    return ''.join('\\x{:02x}'.format(ord(c)) for c in s)

def crypt_str(s):
    new = ''
    for i, c in enumerate(s):
        new += chr(ord(c) ^ ((0x83 + i) % 256))
    return new

def output_header(f):
    f.write('#ifndef __KITESHIELD_OBFUSCATED_STRINGS_H\n')
    f.write('#define __KITESHIELD_OBFUSCATED_STRINGS_H\n')
    f.write(_DEOBF_MACRO)
    f.write('\n')

    for name, cleartext in STRINGS.items():
        encrypted = escape_str(crypt_str(cleartext))
        f.write('/* "{0}" */\n'.format(cleartext))
        f.write('static const char {0}[] = "{1}";\n\n'.format(name, encrypted))

    f.write('\n')
    f.write('#endif /* __KITESHIELD_OBFUSCATED_STRINGS_H */\n')

if __name__ == '__main__':
    output_header(sys.stdout)
