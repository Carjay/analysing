#!/usr/bin/env python

# The MIT License (MIT)
#
# Copyright (c) 2013 Carsten Juttner <carjay@gmx.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#
# Tool to add string annotations to a disassembly dump.
# Uses objdump to generate the asm file then rereads it and scans it for symbol
# references that point into the readonly section(s). It then adds the data
# (we assume it is a string) that is present at that offset into an annotated
# disassembly output.
#

import os
import sys

from asmfile import ASMFile

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("Error: dependency pyelftools missing, see https://github.com/eliben/pyelftools")
    exit(1)

def usage():
    print("Usage: %s <elffile>" % os.path.basename(sys.argv[0]))


def adddbgstr(sec, addr, idx, lines):
    if sec:
        secmin = sec.header['sh_addr']
        secmax = secmin + sec.header['sh_size']

        if (addr >= secmin and addr < secmax):
            strend = addr-secmin
            # we assume it is a string
            while (strend < len(sec.data())) and (sec.data()[strend] != '\x00'):
                strend += 1
            dbgstr = sec.data()[addr-secmin:strend]
            lines[idx] = lines[idx] + ' \"%s\"' % dbgstr.strip()


def main():
    if len(sys.argv) != 2:
        usage()
        return

    elffname = sys.argv[1]
    if not os.path.exists(elffname):
        print("Error: file '%s' does not exist" % elffname)
        return

    # name + ext
    basename = os.path.basename(elffname)
    asmfname = basename + '.asm'

    # dump source
    print("creating assembler output")
    # disassembles Intel style, adds relocation info and uses 'wide' printing
    os.system("objdump -M intel -drw %s > %s" % (elffname, asmfname))

    with open(asmfname, 'r') as asmfh:
        asm = ASMFile(asmfh)

    lines = asm.asmlines[:] # deep copy

    outputfname = basename + '.annotated.asm'
    print("writing merged asm")
    with open(outputfname, 'w') as fw:
        with open(elffname, 'rb') as fh:
            elffile = ELFFile(fh)

            sec = None
            if len(asm.roreloclines): # we have relocation information
                for secname, addr, idx in asm.roreloclines:
                    sec = elffile.get_section_by_name(secname)
                    if not sec:
                        print("warning: assembler file states offset from symbol '%s' which is not a valid ELF section" % secname)
                    else:
                        adddbgstr(sec, addr, idx, lines)
            else: # no relocation information present, so try to find information in load opcodes
                for addr, idx in asm.loadaddrlines:
                    sec = elffile.get_section_by_name('.rodata')
                    if not sec:
                        print("unable to find a section named '.rodata' in elf file, probably different name or no read-only data present")
                    else:
                        adddbgstr(sec, addr, idx, lines)

        for l in lines:
            fw.write(l + '\n')

               


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

