#!/usr/bin/env python

# script to try to reconstruct a kdump vmcore
# that was transferred by FTP through ASCII
# (so all \x0d\0x0a were changed to \x0a)

import os
import sys
import struct
import time
import zlib
import itertools

def getHR(num):
    if num < (1<<10):
        return "%d Byte" % num
    elif num < (1<<20):
        return "%.02f KByte" % (float(num)/(1<<10))
    elif num < (1<<30):
        return "%.02f MByte" % (float(num)/(1<<20))
    elif num < (1<<40):
        return "%.02f GByte" % (float(num)/(1<<30))
    else:
        return "%.02f TByte" % (float(num)/(1<<40))


def trypermuteddecompress(pagebuf, occurencelist):
    # we do this one bit at a time since the probability of only one or maybe a few \x0a changed is higher than
    # they changed all at once, the itertools command creates these combinations for us,
    # see http://stackoverflow.com/questions/1851134/generate-all-binary-strings-of-length-n-with-k-bits-set
    for bitsset in range(1,len(occurencelist)+1):
        print("trying with %d bits set" % bitsset)
        svlist = itertools.combinations(range(len(occurencelist)), bitsset)
        # svlist contains the indices to the \x0a bytes we need to patch up
        for idxlist in svlist:
            last = 0
            tmpbuf = ""
            for permidx in idxlist:
                idx = occurencelist[permidx]
                tmpbuf += pagebuf[last:idx] + '\x0d'
                last = idx
            tmpbuf += pagebuf[last:]

            try:
                uncomppage = zlib.decompress(tmpbuf)
                print("replacing indices %s worked (%d bytes)" % (idxlist, len(uncomppage)))
                return tmpbuf

            except zlib.error, exc:
                #print str(exc)
                pass
    return None


def main():
    if len(sys.argv) != 2:
        print("Usage: %s <vmcore>" % os.path.basename(sys.argv[0]))
        return 1

    vmcore = sys.argv[1]
    if not os.path.exists(vmcore):
        print("Error: vmcore '%s' not found" % vmcore)
        return 1
    
    # the main page descriptor table has been reconstructed manually by
    # looking at the correct offsets, so we now only need to check each
    # compressed piece of memory starting from the lowest address and
    # trying to uncompress it. If it fails then iteratively check all \x0a
    # bytes and try their \x0d\x0a equivalent. This builds upon there not being
    # too many of these sequences
    
    # for now, this script only works natively for x86_64
    
    with open(vmcore, 'rb') as fh:
        buf = fh.read()
        
        utsfmt = "65s65s65s65s65s65s" # sysname, nodename, release, version, machine, domainnname
        timevalfmt = "ll" # time_tv tvsec and suseconds_t tv_usec
        headerfmt = "8si%s%sIiiIIIIIIiP" % (utsfmt, timevalfmt) #
        header = struct.unpack(headerfmt, buf[0:struct.calcsize(headerfmt)])
        signature, header_version = header[0:2]
        uts_sysname, uts_nodename, uts_release, uts_version, uts_machine, uts_domainname = header[2:2+6]
        
        if signature != "KDUMP   ":
            print("Error: signature is not 'KDUMP': '%s'" % signature)
            return 2
        
        if header_version != 4:
            print("Warning: header version %d does not match expected version 4" % header_version)
            return 2
    
        print("uts header:")
        print("  sysname: %s" % uts_sysname.strip('\x00'))
        print("  nodename: %s" % uts_nodename.strip('\x00'))
        print("  release: %s" % uts_release.strip('\x00'))
        print("  version: %s" % uts_version.strip('\x00'))
        print("  machine: %s" % uts_machine.strip('\x00'))
        print("  domainname: %s" % uts_domainname.strip('\x00'))

        time_secs, time_usecs = header[8:10]
        time_usecs = 1000000
        epoch = float(time_secs) + (float(time_usecs)*1e-6)
        
        print("dump created at '%s' local time" % time.ctime(epoch))
    
        headerstatus = header[10]
        print("status: 0x%x" % headerstatus)
        
        block_size = header[11]
        sub_hdr_size = header[12]
        bitmap_blocks = header[13]
        max_mapnr = header[14]
        
        print("block_size: %d" % block_size)
        print("sub_hdr_size: %d" % sub_hdr_size)
        print("bitmap_blocks: %d" % bitmap_blocks)
        print("max_mapnr: %d" % max_mapnr)
        print("  %d bytes of ram mapped" % (block_size*max_mapnr))
        print("  %d bytes of bitmap" % (block_size*bitmap_blocks))

        # structure:
        # HEADER (1 block)
        # SUB_HDR (sub_hdr_size blocks)
        # BITMAP (bitmap_blocks blocks)
        # PAGE DESCRIPTORS (depends on valid bits in bitmap_blocks)
        
        bitmap_offset = (1 + sub_hdr_size) * block_size
        print("  bitmapoffset: 0x%x" % bitmap_offset)

        dataoffset = (1 + sub_hdr_size + bitmap_blocks) * block_size
        print("  dataoffset: 0x%x" % dataoffset)
    
        # dataoffset points to the page_description table
        offsetlist = dict()
        totalcount = 0
        compcount = 0
        uncompcount = 0

        patched_sections = [] # we need to manually inspect these sites
        
        pagedescfmt = "lIIL" # offset, size, flags, page_flags
        pagedescfmtsize = struct.calcsize(pagedescfmt)

        # the reconstruct code makes a lot of assumptions and is not really meant
        # to "always just work"
        # in case of doubt, use a hex editor and check manually

        readoffset = dataoffset
        while readoffset < (len(buf)-dataoffset):
            pdbuf = buf[readoffset:readoffset+pagedescfmtsize]
            cnt = pdbuf.count('\x0a')
            if cnt > 0:
                found = 0
                if cnt > 2:
                    print("buffer has %d 0a" % cnt)
                    print [pdbuf]

                    pd_offset, pd_size, pd_flags, pd_page_flags = struct.unpack(pagedescfmt, pdbuf)
                    print("%x %d %x %x" % (pd_offset, pd_size, pd_flags, pd_page_flags))
                    # we cannot currently deal with this
                    return

                pdbuflist = []
                for idx in range(pagedescfmtsize):
                    if pdbuf[idx] == '\x0a':
                        pdbuflist.append(idx)
                pd_offset, pd_size, pd_flags, pd_page_flags = struct.unpack(pagedescfmt, pdbuf)
                
                # if offset looks strange then replace the 0a here
                if (pdbuf[0:struct.calcsize("l")].count('\x0a') and pd_offset <= readoffset + (pagedescfmtsize * 2)) or (pd_offset > len(buf)):
                    #print("strange offset %d" % pd_offset)
                    pdbuf = pdbuf[0:struct.calcsize("l")-1].replace('\x0a', '\x0d\x0a') + pdbuf[struct.calcsize("l")-1:-1]
                    pd_offset, pd_size, pd_flags, pd_page_flags = struct.unpack(pagedescfmt, pdbuf)
                    found += 1
                    
                # page_flags are always set to 0 in the RHEL6 code... hmm
                # and pd_flags bit indicates page is compressed by ZLIB, RHEL6 does not support anything else
                if (pdbuf[struct.calcsize("l"):].count('\x0a') and (pd_page_flags != 0) or (pd_flags & ~1)):
                    #print("strange flags %d" % pd_offset)
                    pdbuf = pdbuf[0:struct.calcsize("l")] + pdbuf[struct.calcsize("l"):].replace('\x0a', '\x0d\x0a')
                    pdbuf = pdbuf[:-1]
                    pd_offset, pd_size, pd_flags, pd_page_flags = struct.unpack(pagedescfmt, pdbuf)
                    found += 1
                
                if found > 0:
                    buf = buf[0:readoffset] + pdbuf + buf[readoffset+pagedescfmtsize-found:]
           
            pd_offset, pd_size, pd_flags, pd_page_flags = struct.unpack(pagedescfmt, pdbuf)
            #print("%x %d %x %x" % (pd_offset, pd_size, pd_flags, pd_page_flags))
            if (pd_offset == 0): # TODO: parse Bitmap to collect all valid pages
                break
            if pd_offset in offsetlist:
                if offsetlist[pd_offset][0] != pd_size: # sanity check
                    print("Warning: size mismatch for same offset, previously %d, now %d" % (offsetlist[pd_offset][0], pd_size))
                if offsetlist[pd_offset][1] != pd_flags: # sanity check
                    print("Warning: flags mismatch for same offset, previously %d, now %d" % (offsetlist[pd_offset][1], pd_flags))
                if offsetlist[pd_offset][2] != pd_page_flags: # sanity check
                    print("Warning: page_flags mismatch for same offset, previously %d, now %d" % (offsetlist[pd_offset][2], pd_page_flags))
            else:
                if pd_flags & 1:
                    compcount += 1
                else:
                    uncompcount += 1
                offsetlist[pd_offset] = (pd_size, pd_flags, pd_page_flags)
            readoffset += struct.calcsize(pagedescfmt)
            totalcount += 1

            print("scanfixing %x (%s) %d %x %x" % (pd_offset, getHR(pd_offset), pd_size, pd_flags, pd_page_flags))

        print("scanned index, writing fixed version as backup")
        with open(vmcore + '_fixedindex', 'wb+') as fw:
            fw.write(buf)
        
        # some entries appear more than once
        addresses = sorted(offsetlist.keys())
        print("%d pages in list (%d compressed, %d uncompressed), %d total references, range in file is from %d to %d" % (len(addresses), compcount, uncompcount, totalcount, min(addresses), max(addresses)))
        # assume that there is nothing after the final page data
        print("file is %d bytes too short" % (max(addresses)+offsetlist[max(addresses)][0]-len(buf)))

        previousuncompaddr = 0 # only set if previous section was uncompressed
        previousuncompocc = 0 # only set if previous section was uncompressed

        for addridx, addr in enumerate(addresses):
            pd_size = offsetlist[addr][0]
            pd_flags = offsetlist[addr][1]
            sys.stdout.write("%d/%d 0x%x %d..%d %d 0x%x" % (addridx, len(addresses), addr, addr, addr+pd_size-1, pd_size, pd_flags))
            pagebuf = buf[addr:addr+pd_size]

            # how many of 'em are we dealing with?
            occurencelist = []
            for idx in range(len(pagebuf)):
                if pagebuf[idx] == '\x0a':
                    occurencelist.append(idx)
          
            suspicious = len(occurencelist)
            if suspicious:
                sys.stdout.write(" contains %d 0x0a bytes" % suspicious)
                #print [pagebuf]
                
            if pd_flags & 1: # compressed
                try:
                    uncomppage = zlib.decompress(pagebuf)
                    sys.stdout.write(", ok! (%d bytes)\n" % len(uncomppage))
                except zlib.error, exc:
                    # now it gets more complicated...
                    sys.stdout.write(", nok!\n")
                    worked = False

                    # check if we should skip to trying to backtrack
                    if previousuncompaddr == 0 or previousuncompocc == 0:
                        result = trypermuteddecompress(pagebuf, occurencelist)
                        if result is not None:
                            # fix up the source buffer, we always make a copy
                            # this is slow so for huge files we'd need to use subbuffers
                            buf = buf[0:addr] + result + buf[addr+pd_size:]
                            worked = True
                    else:
                        print("uncompressed previous section at %d, trying to patch up" % previousuncompaddr)
                        backtrack = 0
                        startbacktrack = 0

                        # short cut: try to find the zlib header
                        for backtrack in range(0,previousuncompocc+1):
                            # backtrack...
                            if buf[addr-backtrack:addr-backtrack+2] == 'x\x01':
                                startbacktrack = backtrack
                                print("found zlib header at backtrack %d" % startbacktrack)
                                break
                  
                        # a backtrack of 0 is allowed to cover the case where we follow an uncompressed section
                        # but it did not have any \x0d missing
                        for backtrack in range(startbacktrack,previousuncompocc+1):
                            pagebuf = buf[addr-backtrack:addr-backtrack+pd_size]
     
                            # try to decompress
                            try:
                                uncomppage = zlib.decompress(pagebuf)
                                worked = True
                                break
                            except zlib.error, exc:
                                # now it gets more complicated...
                                # we check various permutations
    
                                occurencelist = [] # need to reevaluate
                                for idx in range(len(pagebuf)):
                                    if pagebuf[idx] == '\x0a':
                                        occurencelist.append(idx)
    
                                result = trypermuteddecompress(pagebuf, occurencelist)
                                if result is not None:
                                    # fix up the missing characters
                                    buf = buf[:addr-backtrack] + result + buf[addr-backtrack+pd_size:]
                                    worked = True
                                    break
    
                        # finally fix the difference accumulated by the previous sections by
                        # inserting 'X' as patching any \x0a would be just guesswork (we do not know if it
                        # it even all happened in the previous section as there may be streams of uncompressed
                        # sections which will accumulate missing the \x0d characters)
                        if worked and backtrack > 0:
                            print("worked after backtracking %d bytes" % backtrack)
                            buf = buf[0:previousuncompaddr] + (backtrack * 'X') + buf[previousuncompaddr:]

                    if worked:
                        previousuncompaddr = 0 # reset
                        previousuncompocc  = 0
                        continue
            
                    print("no luck... save what we have and quit")
                    with open(vmcore + '_partialfixed', 'wb+') as fw:
                        fw.write(buf)
                    return

                previousuncompaddr = 0 # reset
                previousuncompocc  = 0
            else:
                # nothing we can do here except for trying to patch it up when
                # things fail at the next compressed section
                previousuncompaddr = addr
                previousuncompocc += len(occurencelist) # accumulate in case there is more than one uncompressed section
                sys.stdout.write('\n')

        print("finished! yeah... writing fixed buffer")

        with open(vmcore + '_fixed', 'wb+') as fw:
            fw.write(buf)

        if len(patched_sections):
            print("Warning: you need to manually inspect these bytes (they were for now simply padded with 'X' characters)")
            for addr,l in patched_sections:
                print("%d..%d length %d" % (addr, addr+l-1, l))
        
            
            



def kbits(n, k):
    result = []
    for bits in itertools.combinations(range(n), k):
        num = 0
        for bit in bits:
            num |= (1<<bit)
        result.append(num)
    return result

#Output: ['1110', '1101', '1011', '0111']

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

