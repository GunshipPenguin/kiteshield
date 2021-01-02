#!/usr/bin/python3

# String obfuscation script, this ensures that no strings exist in the loader
# code that could be useful to a reverse engineer. All potentially useful
# strings should be declared in the STRINGS map and deobfuscated at runtime
# using the DEOBF_STR macro.

import binascii
import sys

STRINGS = {
        # loader/include/anti_debug.h
        'PROC_PATH' : '/proc/',
        'SLASH_STATUS' : '/status',
        'TRACERPID_PROC_FIELD': 'TracerPid:',

        # loader/string.c
        'HEX_DIGITS': '0123456789abcdef'
}

_DEOBF_MACRO = '''
#define DEOBF_STR(str)                                                         \\
  ({ char cleartext[sizeof(str)];                                              \\
     for (int i = 0; i < sizeof(str); i++) {                                   \\
       cleartext[i] = str[i] ^ ((0x83 + i) % 256);                             \\
     };                                                                        \\
     cleartext[sizeof(cleartext) - 1] = '\\0';                                 \\
     cleartext; })

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
