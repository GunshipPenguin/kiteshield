import binascii
import glob
import math
import os
import shutil
import sys

LOADER_DIR = 'src/loaders/impls'
LOADER_OBJ_DIR = 'stub_obj'

BINARY_OUTPUT_DIR = 'stub_bin'
HEADER_OUTPUT_DIR = 'src/loaders'

AS = 'as'
AS_FLAGS = ''

CC = 'cc'
CC_FLAGS = '-nostdlib -nostartfiles -nodefaultlibs -fno-builtin -c -I src/include'

LD = 'ld'
LD_FLAGS = '-T src/loaders/x86_64_linux_elf.lds'

BYTES_PER_LINE = 16


def build_bin_stubs():
    loader_src_files = [os.path.basename(path) for path in glob.glob(os.path.join(LOADER_DIR, 'loader_*.c'))]

    if os.path.exists(LOADER_OBJ_DIR):
        shutil.rmtree(LOADER_OBJ_DIR)

    if os.path.exists(BINARY_OUTPUT_DIR):
        shutil.rmtree(BINARY_OUTPUT_DIR)

    os.mkdir(LOADER_OBJ_DIR)
    os.mkdir(BINARY_OUTPUT_DIR)

    for loader_src_file in loader_src_files:
        loader_obj_file = loader_src_file.replace('.c', '.o')
        loader_src_path = os.path.join(LOADER_DIR, loader_src_file)
        loader_obj_path = os.path.join(LOADER_OBJ_DIR, loader_obj_file)

        entry_src_file = loader_src_file.replace('loader_', 'entry_').replace('.c', '.S')
        entry_obj_file = entry_src_file.replace('.S', '.o')
        entry_src_path = os.path.join(LOADER_DIR, entry_src_file)
        entry_obj_path = os.path.join(LOADER_OBJ_DIR, entry_obj_file)

        if not os.path.isfile(entry_src_path):
            sys.stderr.write('Could not find entry file %s, skipping\n' % entry_src_path)
            continue

        binary_output_file = loader_src_file.replace('loader_', 'stub_').replace('.c', '.bin')
        binary_output_path = os.path.join(BINARY_OUTPUT_DIR, binary_output_file)

        os.system('%s %s %s -o %s' % (AS, AS_FLAGS, entry_src_path, entry_obj_path))
        os.system('%s %s %s -o %s' % (CC, CC_FLAGS, loader_src_path, loader_obj_path))
        os.system('%s %s %s %s -o %s' % (LD, LD_FLAGS, entry_obj_path, loader_obj_path, binary_output_path))

def build_header_stubs():
    for stub_bin_path in glob.glob(os.path.join(BINARY_OUTPUT_DIR, '*.bin')):
        header_file_name = os.path.basename(stub_bin_path).replace('.bin', '.h')
        header_path = os.path.join(HEADER_OUTPUT_DIR, header_file_name)

        bin_file = open(stub_bin_path, 'rb')
        header_file = open(header_path, 'w')

        stub_var_name = header_file_name.replace('.h', '')

        byte_strs = \
            ['0x' + binascii.hexlify(byte).decode('ascii') for byte in iter(lambda: bin_file.read(1), b'')]
        byte_strs_it = iter(byte_strs)

        header_file.writelines(['#ifndef KITESHIELD_%s_H\n' % stub_var_name.upper(),
                                '#define KITESHIELD_%s_H\n\n' % stub_var_name.upper(),
                                'char %s[%d] = {\n' % (stub_var_name, len(byte_strs))])

        for line_num in range(math.ceil(len(byte_strs) / BYTES_PER_LINE)):
            line = [next(byte_strs_it) for _ in range(min(BYTES_PER_LINE, len(byte_strs) - line_num * BYTES_PER_LINE))]
            header_file.writelines([
                '\t',
                ', '.join(line),
                ',\n'
            ])

        header_file.write('};\n\n')
        header_file.write('#endif\n')

        bin_file.close()
        header_file.close()


build_bin_stubs()
build_header_stubs()

shutil.rmtree(LOADER_OBJ_DIR)
shutil.rmtree(BINARY_OUTPUT_DIR)
