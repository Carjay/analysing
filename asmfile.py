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
# ASMFile
# parsing vehicle for files disassembled by objdump
#

import re


class ASMFile:
    _asmfh = None # asm file handle
    _romatchers = None # matching potential places in code that may use static debug strings

    # public variables
    asmlines = None # list of all asm lines
    loadaddrlines = None # list of tuples: (address, lineindex)
    roreloclines = None # list of tuples: (sectionname, address, lineindex)
    
    # matchers are executed until a valid one is found (or none)
    
    def __init__(self, asmfh):
        self._asmfh = asmfh
        self.asmlines = []
        self.loadaddrlines = []
        self.roreloclines  = []

        self._romatchers = []
        self._romatchers = (
            # matcher, what parsing function to run
            ( re.compile('.+R_X86_64_32S\s+(\..+)\s+'), self._rorelocparse ), # only accept symbols starting with '.' which should be ELF sections
            ( re.compile('.+\smov\s+.+,(0x[0-9a-fA-F]+)\s+'), self._loadaddrparse ),
        )

        self._parse()


    def _parse(self):
        self._asmfh.seek(0)
        lineit = iter(self._asmfh.readline, '')
        for idx, l in enumerate(lineit):
            self.asmlines.append(l.strip())
            for regexp, parsingfunc in self._romatchers:
                m = regexp.match(l)
                if m:
                    parseddata = parsingfunc(idx, m)
                    break # do not apply any more matchers for this line


    def _rorelocparse(self, idx, m):
        parseddata = []
        offsetinfo, = m.groups()
        m = re.match('(.+)\+(0x[0-9a-fA-F]+)', offsetinfo)
        if m:
            secname, addr = m.groups()
            addr = int(addr, 16)
            self.roreloclines.append( ( secname, addr, idx ) )


    def _loadaddrparse(self, idx, m):
        parseddata = []
        addr, = m.groups()
        addr = int(addr, 16)
        self.loadaddrlines.append( ( addr, idx ) )



