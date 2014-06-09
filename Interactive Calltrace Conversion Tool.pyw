#!/usr/bin/python

##############################
# AUTHOR: Aivin V. Solatorio #
#                            #
# DATE:   03.18.2014         #
# ddump.exe interface        #
##############################

import wx
import wx.xrc
import md5, os, re, subprocess, sys, time


symbaddr_script = r'''#!/usr/bin/python

##########################
# AUTHOR: Martin Mueller #
#                        #
# DATE:   08.11.2010     #
##########################

import os,sys,re,string,bisect
from sets import Set

#############
# FUNCTIONS #
#############



def usage():
    print "Usage:"
    print ""
    print "   [ python ] symbaddr.py { CT_LINUX <exe file> <log file> }"
    print "                        | { CT_LINUX_WITH_MAPS <log file> <maps file> }"
    print "                        | { CT_OSE <log file> <map file> }"
    print "                        | { MT <log file> <maps file> }"
    print ""
    print "   CT_LINUX:           convert output with calltraces (offsets are contained in source already)"
    print "   CT_LINUX_WITH_MAPS: convert output with calltraces (offsets are contained in maps file)"
    print "   CT_OSE:             convert output with calltraces"
    print "   MT:                 convert mtrace output"
    print ""
    print "Example:"
    print "   ./symbaddr.py CT_LINUX CCSDaemoneExe mema_dump.txt"
    print "   ./symbaddr.py CT_LINUX_WITH_MAPS SYSLOG_132.LOG maps"
    print "   ./symbaddr.py CT_OSE heapdump.txt FCMD-MC-RT_PS100302.map"
    print "   ./symbaddr.py CT_OSE SYSLOG_026.LOG FCMD-MC-RT_TESTBIN.map"
    print "   ./symbaddr.py MT mtrace.out maps"
    print ""

def getLibPath():
    """ decompose LD_LIBRARY_PATH into its single path components and return a list of them """
    lp = os.environ.get("LD_LIBRARY_PATH")
    if None == lp:
        print "!!! LD_LIBRARY_PATH is not set !!!"
        return []
    lpa = lp.split(':')
    print "... components of LD_LIBRARY_PATH: ..."
    for p in lpa:
        print "    %s" % (p)
    return lpa

###############################################
# BINARY CLASS HIERARCHY (for LINUX binaries) #
###############################################

#
#   LinkedBinary
#     ^      ^
#     |      |
#    Exe  DynLib
#

class LinkedBinary:
    """
    Base class for any binaries which contain symbols.
    (These binaries might be executables or dynamic libs.)
    """

    def __init__(self, binname, baseaddr):
        """ initializes the instance by adding symbols, if available """

        self.name = binname                # name of the binary
        self.baseaddr = baseaddr           # base address it is mapped to
        self.begaddr = 0                   # begin (first) address: will be filled by loadSymbols() later
        self.endaddr = 0xffffffff          # end (last) address: will be filled by loadSymbols() later
        self.path = self.findPath(binname) # full path of the binary
        self.symblst = {}                  # symbol dictionary (absolute address is the key)

        if self.exists():
            self.loadSymbols()
            if self.hasSymbols():
                print "... %s: %d symbols loaded (%x - %x) ..." % (self.name, self.length(), self.begaddr, self.endaddr)
            else:
                print "!!! %s: no symbols available !!!" % (self.name)
        else:
            print "!!! %s: not found !!!" % self.name

    def findPath(self, binname):
        """ returns the absolute path of the binary (has to be redefined in subclasses) """
        pass

    def exists(self):
        """ returns True if binary file exists, False otherwise """
        if None == self.path:
            return False
        return True

    def getName(self):
        """ returns file name of binary """
        return self.name

    def getPath(self):
        """ returns path of binary """
        return self.path

    def length(self):
        """ returns number of text segment symbols found """
        return len(self.symblst)

    def hasSymbols(self):
        """ returns True if text segment symbols are available, False otherwise """
        if 0 == self.length():
            return False
        return True

    def loadSymbols(self):
        """ fill dictionary with available symbols """

        if self.exists():
            # following nm command lists all textsegment symbols
            cmd = "nm --defined-only -n " + self.path + " 2>/dev/null | grep -i \' t \'"

            # following regular expression is used for getting the symbol-address relation
            # from the output of the nm command.
            #
            # Examples for matching lines:
            #   0000000000141a55 T ferror_mem_func
            #   0000000000141a68 T fill_memory_filefunc
            #   0000000000141ae0 t __fixunssfdi
            #   0000000000141b60 t __udivdi3
            #          ^                    ^
            #   |-- group(1) --|   |----- group(2) -----|
            #    absolute or              symbol
            #    relative addr.

            p = re.compile('(^[0-9,a-f]+) [t] (.+)', re.IGNORECASE)

            addr = 0
            for line in os.popen(cmd).readlines():
                m = p.match(line)
                if m:
                    addr = string.atoi(m.group(1),16) + self.baseaddr # calculate absolute address
                    symb = m.group(2)
                    self.symblst[addr] = symb
                    if 0 == self.begaddr: self.begaddr = addr
            self.endaddr = addr

    def findSymbol(self, searchaddr, withOffset = False):
        """ lookup for symbol with given address 
            (if available, then by default the symbol alone is returned,
             optionally also the symbol plus offset might be returned) """
        if self.baseaddr < searchaddr < self.endaddr:
            prevaddr = None
            for addr in sorted(self.symblst.keys()):
                if prevaddr != None:
                    if addr > searchaddr >= prevaddr:
                        if withOffset:
                            offset = searchaddr - prevaddr
                            if 0 != offset:
                                return self.symblst[prevaddr] + " + " + hex(offset)
                        return self.symblst[prevaddr]
                prevaddr = addr
        return None

    def printSymbols(self):
        """ print all available symbols """
        for addr in sorted(self.symblst.keys()):
            print hex(addr) + " -> " + self.symblst[addr]

class Exe(LinkedBinary):
    """
    Class for executable binaries which contain symbols.

    Note:
        - base address for symbols is always 0 in that case
        - the binary is expected to be contained in current working directory
          (where the script is called from)
    """

    def __init__(self, exename):
        LinkedBinary.__init__(self, exename, 0x0)

    def findPath(self, exename):
        """ if existing, return path of executable """
        tmppath = os.path.join(".", exename)
        if os.path.isfile(tmppath):
            return tmppath

class DynLib(LinkedBinary):
    """
    Class for dynamic libraries which contain symbols.

    Note:
        - base address for symbols has to be passed through constructor
        - the binary is expected to be found through LD_LIBRARY_PATH variable
    """

    ld_library_path = getLibPath()

    def __init__(self, libname, baseaddr):
        LinkedBinary.__init__(self, libname, baseaddr)

    def findPath(self, libname):
        """ if lib exists in one of LD_LIBRARY_PATH components, return its path """
        for p in self.ld_library_path:
            tmppath = os.path.join(p, libname)
            if os.path.isfile(tmppath):
                return tmppath


##############################
# SYMBOL CONTAINER HIERARCHY #
##############################

#
#                     SymbolContainer
#                       ^         ^
#                       |         |
# MapFileSymbolContainerOse     BinarySymbolContainerLinux
#

class SymbolContainer:
    """
    Base class for the container that holds all symbols
    """

    def __init__(self, mapspath):
        self.file = None
        if os.path.isfile(mapspath):
            self.file = mapspath
        else:
            print"!!! maps file %s not found !!!" % (mapspath)
            return
        self.readSymbols()
        self.cache = {}

    def readSymbols():
        pass

    def findSymbol(self, searchaddr, withOffset = False):
        pass

    def getSymbol(self, addr, withOffset = False):
        try:
            symb = self.cache[addr]
        except:
            symb = None

        if None != symb:
            if symb == ">no<": return None
        else:
            symb = self.findSymbol(addr, withOffset)
            if None == symb:
                self.cache[addr] = ">no<"
            else:
                self.cache[addr] = symb
        return symb

class BinarySymbolContainerLinux(SymbolContainer):
    """
    Class that holds all symbols found in LINUX binaries (executables and libraries)
    """

    def __init__(self, offsetFilePath, exebinname = None):
        self.binlst = []
        if None != exebinname:
            bin = Exe(exebinname)
            if bin.hasSymbols(): self.binlst.append(bin)
        SymbolContainer.__init__(self, offsetFilePath)

    def readSymbols(self):
        """ returns a list of all binary instances (derived from class LinkedBinary)
            with available symbols, referred by the related maps file """

        # following regular expression is used for getting the base-address-to-binary-name relation
        # from the maps file.
        #
        # Examples for matching lines:
        #   00388000-00391000 r-xp 00000000 08:01 259359                             /lib/libcrypt-2.5.so
        #   00391000-00392000 r-xp 00008000 08:01 259359                             /lib/libcrypt-2.5.so
        #      => Note: only the first line (of the two above) is relevant, since it contains the
        #               real base address!
        #
        #   08048000-0819c000 r-xp 00000000 00:2b 10617168                           /root/CCSDaemonExe
        #   f7d5b000-f7ee6000 r-xp 00000000 00:2b 10611580                           /lib/libCCS.so
        #       ^                                                                          ^
        #  |group(1)|                                                                |---group(2)-----|
        # base address                                                                 binary path

        mapsbinre = re.compile('(^[0-9,a-f]+)-[0-9,a-f]+ r-xp [0-9,a-f]+ .+ (\D.+)$', re.IGNORECASE)

        # following regular expression is used to differ executables from dynamic libraries.
        # It is applied on the full binary path (gained through group(2) of regulare expression above)
        #
        # Examples for matching patterns:
        #   /lib/libcrypt-2-5.so
        #   /lib/libCCS.so
        #   /usr/lib/libstdc++.so.6.0.8

        sore = re.compile('.*\.so[\.]{0,1}')

        # following regular expression is used for getting the binary-name-to-base-address relation
        # from the 'Dynamic Libs' header of the AaMemAdapter dump.
        #
        # Examples for matching lines:
        #   /lib/libCCS.so: f7d0d000
        #   /usr/lib/libz.so.1: f7cfa000
        #   /usr/lib/libcurl.so.4: f7cc9000
        #            ^                ^
        #   |--- group(1) ------| |group(2)|
        #       binary path      base address

        headbinre = re.compile('(^\/.*): ([0-9,a-f]+)$', re.IGNORECASE)

        binset = Set() # set of binaries where the first text segment line of the maps file was already handled

        inp = open(self.file, "r")
        for line in inp.readlines():
            m = mapsbinre.match(line)
            if m:
                baseaddr = string.atoi(m.group(1),16)
                (binpath, binname) = os.path.split(m.group(2))
                # only if the binary is not yet contained in the set, then it is the very first line
                # in the maps file occuring for this binary
                #    => only then we can extract the base address (see example for /lib/libcrypt-2.5.so above )
                if binname not in binset:
                    if sore.match(binname):
                        bin = DynLib(binname, baseaddr)
                    else:
                        bin = Exe(binname)
                    binset.add(binname)
                    if bin.hasSymbols(): self.binlst.append(bin)
            else:
                m = headbinre.match(line)
                if m:
                    (binpath, binname) = os.path.split(m.group(1))
                    baseaddr = string.atoi(m.group(2),16)
                    bin = DynLib(binname, baseaddr)
                    if bin.hasSymbols(): self.binlst.append(bin)
        inp.close()

    def findSymbol(self, searchaddr, withOffset = False):
        symb = None
        for bin in self.binlst:
            symb = bin.findSymbol(searchaddr, withOffset)
            if None != symb: break
        return symb

class MapFileSymbolContainerOse(SymbolContainer):
    """
    Class that holds all symbols found in the OSE map file
    """

    def __init__(self, mapspath):
        self.addresses = []
        self.symblst = {}
        SymbolContainer.__init__(self, mapspath)

    def readSymbols(self):
        """ fill dictionary with symbols from map file """

        # following regular expression is used for getting the symbol-address relation
        # from OSE map files:
        #
        # Examples for matching lines:
        #                                                           absolute
        #                  symbol                                     adr.
        #   |------------------- group(1) -------------------------|-group(2)-|
        #   takeEvent__41FDCLConfigurationChecker_bufferingUpdatesFs 00f287a8  0000059c
        #   _STI__FDCLConfigurationChecker_cpp_0665137f 00f28d44   00000130
        #       __ct__Q2_3std124_Tmap_traits__tm__103_iP8FDCLUnitQ2_3std13less__tm__2_iQ2_3std52allocator__tm__35_Q2_3std25pair__tm__13_CiP8FDCLUnitXCbL_1_0FZ3Z 00f28f84  00000058 C_Application\SC_OAM\Target\FSMB\FCMA\F_OamSwTarget.a[FDCLConfigurationChecker.o]

        p = re.compile('^\s*(\w+)\s+([0-9a-f]+)\s+([0-9a-f])+(\s\S+)?\s*$', re.IGNORECASE)

        addr = 0
        size = 0

        inp = open(self.file, "r")
        for line in inp.readlines():
            m = p.match(line)
            if m:
                symb = m.group(1)
                addr = string.atoi(m.group(2),16)
                size = string.atoi(m.group(3),16)
                self.symblst[addr] = symb
        inp.close()
        self.addresses = sorted(self.symblst.keys())

    def findSymbol(self, searchaddr, withOffset = False):
        bisectPos = bisect.bisect(self.addresses, searchaddr)
        if bisectPos > 0:
            prevaddr = self.addresses[bisectPos - 1]
            if withOffset:
                offset = searchaddr - prevaddr
                if 0 != offset:
                    return self.symblst[prevaddr] + " + " + hex(offset)
            return self.symblst[prevaddr]
        return None


#############################
# CONVERTER CLASS HIERARCHY #
#############################

#
#                                     Converter
#                                      ^     ^
#                                      |     |
#                     +----------------+     +-------------------+
#                     |                                          |
#            CalltraceConverter                                  |
#              ^            ^                                    |
#              |            |                                    |
# CalltraceConverterOse CalltraceConverterLinux         MtraceConverterLinux
#

class Converter:
    """
    Base class for address to symbol converters.
    """

    def __init__(self, srcpath):
        self.file = None
        if os.path.isfile(srcpath):
            self.file = srcpath
        else:
            print "!!! source file %s not found !!!" % (srcpath)
        self.symbContainer = None # depending on the container, added later in derived subclasses,
                                  # the converter acts either for OSE or LINUX

    def convert(self):
        """ performs the individual conversion (has to be redefined in subclasses) """
        pass

class CalltraceConverter(Converter):
    """
    Converter base class for calltraces in AaMem notation: [ adr 1 ]<-[ adr 2 ]<- ...
    (It operates on all files that migth contain the AaMem calltrace pattern, no matter whether
     produced on OSE or LINUX platforms.)
    """

    def __init__(self, srcpath):
        Converter.__init__(self, srcpath)

    def convert(self):
        """ performs the individual conversion for calltrace pattern """

        if None == self.file: return

        # following regular expression is used for getting the calltraces (in CC&S notation)
        # from any output.
        #
        # Examples for matching lines:
        #
        #   (1) from syslog files:
        #   014694 30.09 09:38:24.125  [192.168.255.1]  0c FCM-1011 <01.01 00:00:00.000000> 0 ERR/CCS/AaError, Call trace: [0047CA8C]<-[0047E2A8]
        #   <-[0047E518]<-[0047E710]<-[004A69D8]<-[00204230]<-[0023FE7C]<-[00279108]<-[001FDB00]<-
        #   035490 30.09 12:52:37.312  [192.168.255.1]  6f FCM-1011 <01.01 00:04:20.971279> 80092 ERR/CCS/AaMemAdapter, Quarantine violation!
        #   (address=BF9484, alloc. data: EU=10092, size=10, stack=[2EFD88]<-[2EF9C8]<-[28F464]<-[28E6E8]<-)#
        #
        #   (2) from OSE heap dump:
        #   70090    ,   16384, 01.01 00:04:50, AaFileCompression.c:574         , [22116C]<-[21DEB8]<-[1F3BD4]<-[1F16B4]<-
        #   70090    ,      16, 01.01 00:04:50, AaFile.c:815                    , [1DDB18]<-[220F5C]<-[21DEB8]<-[1F3BD4]<-
        #
        #   (3) from Linux heap dump:
        #   27       ,     136, 01.10 11:45:59, [197D6A]<-[321E54]<-[F7E58F9D]<-[F7E2E6F4]<-[F7E2C1D7]<-[F7EA2CCB]<-
        #   8        ,      52, 01.10 11:45:48, [F7E59679]<-[F7E6BB2B]<-[F7E826CC]<-[F7E84A95]<-[F7E869DD]<-[F7E86C56]<-
        #
        #                                               6 * |-group(3)-|
        #                                                    nested adr.
        #                                                      pattern
        #   |----------- group(1) --------------|-------------------------- group(2) ----------------------------------|--- group(4) ---|
        #             begin of line                                      complete calltrace                               possible rest
        #                                                                                                                    of line

        btre = re.compile('(.*[\s=]+)((\[[0-9,a-f]+\]<-)+)(.*)', re.IGNORECASE)

        # following regular expression is used for getting the single address patterns from calltraces.
        #
        # Examples for matching patterns:
        #    [197D6A]
        #    [F7E826CC]

        addrre = re.compile('[0-9,a-f]+', re.IGNORECASE)

        inp = open(self.file, "r")
        for line in inp.readlines():
            bt = btre.match(line)
            if bt:
                btstr = ""
                addrstrlst = addrre.findall(bt.group(2))
                for addrstr in addrstrlst:
                    addr = string.atoi(addrstr,16)
                    symb = self.symbContainer.getSymbol(addr)

                    if None != symb:
                        btstr += "[" + symb + "]<-"
                    else:
                        btstr += "[" + addrstr + "]<-"
                print bt.group(1) + btstr + bt.group(4)
            else:
                print line.replace("\n","")
        inp.close()


class CalltraceConverterOse(CalltraceConverter):
    """
    Class for converting the output (produced by OSE loads) containing any calltraces
    """

    def __init__(self, srcpath, mappath):
        CalltraceConverter.__init__(self, srcpath)
        self.symbContainer = MapFileSymbolContainerOse(mappath)


class CalltraceConverterLinux(CalltraceConverter):
    """
    Class for converting the output (produced by LINUX loads) containing any calltraces
    """

    def __init__(self, exebinname, srcpath, mapspath = None):
        CalltraceConverter.__init__(self, srcpath)

        if None == mapspath:
            # if source file (e.g. AaMem heap trace dump) contains header with base addresses
            self.symbContainer = BinarySymbolContainerLinux(srcpath, exebinname)
        else:
            # here the base addresses are gained from maps file (in this case exebinname is not necessary)
            # e.g. necessary for syslog files with contained calltraces
            self.symbContainer = BinarySymbolContainerLinux(mapspath)


class MtraceConverterLinux(Converter):
    """
    Class for converting output of mtrace
    """

    def __init__(self, mtracepath, mapspath):
        Converter.__init__(self, mtracepath)
        self.symbContainer = BinarySymbolContainerLinux(mapspath)

    def convert(self):
        """ replace all addresses with symbols (if available) in mtrace output """

        if None == self.file: return

        # following regular expression is used for replacing the absolute function address by
        # a symbol.
        #
        # Examples for matching lines:
        #   0x094edfd0     0x90  at 0x197d6a
        #   0x094fa350     0x38  at 0xf7deeda9
        #   0x094fa398     0x3c  at 0xf7dadd41
        #   0x094fa3d8     0x10  at 0xf7df3c7b
        #              ^                 ^
        #   |------ group(1) ------|-group(2)-|
        #     memory base address    func.
        #     and block size         address

        p = re.compile('(^0x[0-9,a-f]+.* at )(0x[0-9,a-f]+)$', re.IGNORECASE)

        inp = open(self.file, "r")
        for line in inp.readlines():
            m = p.match(line)
            if  m:
                addr = string.atoi(m.group(2),16)
                symb = self.symbContainer.getSymbol(addr)
                if None != symb:
                    print m.group(1) + symb
                    continue
            print line.replace("\n","")
        inp.close()

########
# MAIN #
########

def main(argv=sys.argv):

    if len(argv) == 4 and "CT_LINUX" == argv[1]:
        translator = CalltraceConverterLinux(argv[2], argv[3])
    elif len(argv) == 4 and "CT_LINUX_WITH_MAPS" == argv[1]:
        translator = CalltraceConverterLinux("dummy", argv[2], argv[3])
    elif len(argv) == 4 and "CT_OSE" == argv[1]:
        translator = CalltraceConverterOse(argv[2], argv[3])
    elif len(argv) == 4 and "MT" == argv[1]:
        translator = MtraceConverterLinux(argv[2], argv[3])
    else:
        usage()
        return 2

    translator.convert()

    return 0

if __name__ == "__main__":
    sys.exit(main())'''



class AppFrame ( wx.Frame ):
    
    def __init__( self, parent, title ):
        wx.Frame.__init__ ( self, parent, id = wx.ID_ANY, title = title, pos = wx.DefaultPosition, size = wx.Size( 775,600 ), style = wx.DEFAULT_FRAME_STYLE|wx.TAB_TRAVERSAL )
        
        self.SetSizeHintsSz( wx.Size( 775,600 ), wx.DefaultSize )
        
        self.menu_bar = wx.MenuBar( 0 )
        self.file_menu = wx.Menu()
        self.exit_item = wx.MenuItem( self.file_menu, wx.ID_ANY, u"Exit", " Terminate the program", wx.ITEM_NORMAL )
        self.file_menu.AppendItem( self.exit_item )
        
        self.menu_bar.Append( self.file_menu, u"File" ) 
        
        self.help_menu = wx.Menu()
        self.about_item = wx.MenuItem( self.help_menu, wx.ID_ANY, u"About", " Information about this program", wx.ITEM_NORMAL )
        self.help_menu.AppendItem( self.about_item )
        
        self.readme_item = wx.MenuItem( self.help_menu, wx.ID_ANY, u"README", " Instructions on how to use this tool.", wx.ITEM_NORMAL )
        self.help_menu.AppendItem( self.readme_item )
        
        self.menu_bar.Append( self.help_menu, u"Help" ) 
        
        self.SetMenuBar( self.menu_bar )
        
        body_sizer = wx.BoxSizer( wx.VERTICAL )
        
        path_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.path_panel = wx.Panel( self, wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, wx.TAB_TRAVERSAL )
        path_separator_sizer = wx.BoxSizer( wx.VERTICAL )
        
        ddump_staticbox_sizer = wx.StaticBoxSizer( wx.StaticBox( self.path_panel, wx.ID_ANY, u"Path to ddump" ), wx.HORIZONTAL )
        
        ddump_load_button_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.ddump_load_button = wx.Button( self.path_panel, wx.ID_ANY, u"Load ddump", wx.DefaultPosition, wx.DefaultSize, 0 )
        ddump_load_button_sizer.Add( self.ddump_load_button, 0, wx.ALL, 5 )
        
        
        ddump_staticbox_sizer.Add( ddump_load_button_sizer, 0, wx.EXPAND, 0 )
        
        ddump_path_display_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.ddump_path_display = wx.TextCtrl( self.path_panel, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, wx.TE_READONLY )
        ddump_path_display_sizer.Add( self.ddump_path_display, 0, wx.ALL|wx.EXPAND, 5 )
        
        
        ddump_staticbox_sizer.Add( ddump_path_display_sizer, 7, wx.EXPAND, 0 )
        
        
        path_separator_sizer.Add( ddump_staticbox_sizer, 1, wx.EXPAND, 0 )
        
        map_staticbox_sizer = wx.StaticBoxSizer( wx.StaticBox( self.path_panel, wx.ID_ANY, u"Path to map" ), wx.HORIZONTAL )
        
        map_load_button_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.map_load_button = wx.Button( self.path_panel, wx.ID_ANY, u"Load map", wx.DefaultPosition, wx.DefaultSize, 0 )
        map_load_button_sizer.Add( self.map_load_button, 0, wx.ALL, 5 )
        
        
        map_staticbox_sizer.Add( map_load_button_sizer, 0, wx.EXPAND, 0 )
        
        map_path_display = wx.BoxSizer( wx.VERTICAL )
        
        self.map_path_display = wx.TextCtrl( self.path_panel, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, wx.TE_READONLY )
        map_path_display.Add( self.map_path_display, 0, wx.ALL|wx.EXPAND, 5 )
        
        
        map_staticbox_sizer.Add( map_path_display, 7, wx.EXPAND, 0 )
        
        
        path_separator_sizer.Add( map_staticbox_sizer, 1, wx.EXPAND, 0 )
        
        
        self.path_panel.SetSizer( path_separator_sizer )
        self.path_panel.Layout()
        path_separator_sizer.Fit( self.path_panel )
        path_sizer.Add( self.path_panel, 1, wx.EXPAND |wx.ALL, 0 )
        
        
        body_sizer.Add( path_sizer, 0, wx.EXPAND, 0 )
        
        input_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.input_panel = wx.Panel( self, wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, wx.TAB_TRAVERSAL )
        input_separator_sizer = wx.BoxSizer( wx.VERTICAL )
        
        input_staticbox_sizer = wx.StaticBoxSizer( wx.StaticBox( self.input_panel, wx.ID_ANY, u"Enter OSE calltrace below and press convert. Accepted format [45D604]<-[1C97C8]<-... or [__nw__FUi]<-..." ), wx.HORIZONTAL )
        
        input_display_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.input_display = wx.TextCtrl( self.input_panel, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, 0 )
        input_display_sizer.Add( self.input_display, 1, wx.ALL|wx.EXPAND, 5 )
        
        
        input_staticbox_sizer.Add( input_display_sizer, 7, wx.EXPAND, 5 )
        
        input_convert_button_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.input_convert_button = wx.Button( self.input_panel, wx.ID_ANY, u"Convert", wx.DefaultPosition, wx.DefaultSize, 0 )
        input_convert_button_sizer.Add( self.input_convert_button, 0, wx.ALL, 5 )
        
        
        input_staticbox_sizer.Add( input_convert_button_sizer, 0, wx.EXPAND, 5 )
        
        
        input_separator_sizer.Add( input_staticbox_sizer, 1, wx.EXPAND, 5 )
        
        
        self.input_panel.SetSizer( input_separator_sizer )
        self.input_panel.Layout()
        input_separator_sizer.Fit( self.input_panel )
        input_sizer.Add( self.input_panel, 1, wx.EXPAND |wx.ALL, 0 )
        
        
        body_sizer.Add( input_sizer, 0, wx.EXPAND, 5 )
        
        output_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.actual_call_stack_panel = wx.Panel( self, wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, wx.TAB_TRAVERSAL )
        actual_call_stack_sizer = wx.BoxSizer( wx.VERTICAL )
        
        self.actual_call_stack_label = wx.StaticText( self.actual_call_stack_panel, wx.ID_ANY, u"Actual Call Stack", wx.DefaultPosition, wx.DefaultSize, 0 )
        self.actual_call_stack_label.Wrap( -1 )
        actual_call_stack_sizer.Add( self.actual_call_stack_label, 0, wx.ALIGN_CENTER|wx.ALL, 5 )
        
        self.actual_call_stack_display = wx.TextCtrl( self.actual_call_stack_panel, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, wx.TE_MULTILINE|wx.TE_READONLY )
        actual_call_stack_sizer.Add( self.actual_call_stack_display, 1, wx.ALL|wx.EXPAND, 5 )
        
        
        self.actual_call_stack_panel.SetSizer( actual_call_stack_sizer )
        self.actual_call_stack_panel.Layout()
        actual_call_stack_sizer.Fit( self.actual_call_stack_panel )
        output_sizer.Add( self.actual_call_stack_panel, 1, wx.EXPAND |wx.ALL, 0 )
        
        
        body_sizer.Add( output_sizer, 4, wx.EXPAND, 5 )
        
        
        self.SetSizer( body_sizer )
        self.Layout()
        self.status_bar = self.CreateStatusBar( 1, wx.ST_SIZEGRIP, wx.ID_ANY )
        
        self.Centre( wx.BOTH )
        
        # Connect Events
        self.Bind( wx.EVT_MENU, self.Exit, id = self.exit_item.GetId() )
        self.Bind( wx.EVT_MENU, self.About, id = self.about_item.GetId() )
        self.Bind( wx.EVT_MENU, self.Readme, id = self.readme_item.GetId() )
        self.Bind(wx.EVT_CLOSE, self.Exit)
        self.ddump_load_button.Bind( wx.EVT_BUTTON, self.OnDdumpButtonClick )
        self.map_load_button.Bind( wx.EVT_BUTTON, self.OnMapButtonClick )
        self.input_convert_button.Bind( wx.EVT_BUTTON, self.OnConvertButtonClick )

        self.status_bar.SetStatusText('Idle')
        # Init variables
        #
        self.ddump_path = ''
        self.map_path = ''
        self.input_calltrace = ''
        self.input_calltrace_file_name = '.input_calltrace'
        self.temp_symb_file_name = '.symb_file'
        self.temp_file_to_ddump_interface = '.temp_file'
        self.temp_actual_file_name = '.actual_file'

        # Create symbaddr.py
        #
        symbaddr_script_file = file("symbaddr.py", 'w')
        symbaddr_script_file.write(symbaddr_script)
        symbaddr_script_file.close()

    def __del__( self ):
        pass

    def Exit( self, event ):
        proc = subprocess.call(["del", "symbaddr.py", self.input_calltrace_file_name, self.temp_symb_file_name, self.temp_file_to_ddump_interface, self.temp_actual_file_name], shell=True)
        self.Destroy()

    def About( self, event ):
        dlg = wx.MessageDialog( self, "A graphical user interface for interactive conversion of OSE calltrace.\n\nAuthor: Aivin V. Solatorio\nE-mail: aivin.solatorio.ext@nsn.com\nRelease date: March 18, 2014", "About ICC Tool", wx.OK)
        dlg.ShowModal()
        dlg.Destroy()

    def Readme( self, event ):
        dlg = wx.MessageDialog( self, "Usage guide:\n\n1) Load ddump.exe either from diab version 5.0.3 or 5.3.2\n\n2) Load the appropriate map file from BTS build.\n\n3) Input raw calltrace or symbolic address in the input row.\n    Example:\n        [2566288]<-[6F9830]<-[6F90E8]<-[1C7F7C]<-\n    or\n        [rootState_dispatchEvent__10OMReactiveFs]<-[processEvent__10OMReactiveFP9IOxfEvent]<-\n\n4) Press convert and the actual trace will be shown in the display.", "README", wx.OK)
        dlg.ShowModal()
        dlg.Destroy()

    def OnDdumpButtonClick( self, event ):
        ddump_path_dlg = wx.FileDialog(self, wildcard = '*.exe', style=wx.OPEN)
        if ddump_path_dlg.ShowModal():
            # Validate if the submitted executable is indeed a valid ddump.exe - Acceptable versions are ddump ver 5.0.3 and 5.3.2
            #
            valid_md5_values_for_ddump = ['ebffb3e6b3c996256d5d59295f79d4f7', 'd1a2fc60eec62833206aed99f42a49de'] #[ddump ver. 5.0.3, ddump ver. 5.3.2]
            tempDdumpPath = ddump_path_dlg.GetPath()
            tempDdump_md5 = md5.md5(open(tempDdumpPath).read()).hexdigest()

            if tempDdump_md5 in valid_md5_values_for_ddump:
                self.ddump_path = tempDdumpPath
                self.ddump_path_display.SetValue(self.ddump_path)
                self.status_bar.SetStatusText('ddump path loaded.')
            else:
                dlg = wx.MessageDialog( self, "An invalid executable is loaded.\nPlease use ddump.exe from diab ver. 5.0.3 or ver. 5.3.2 only.", "Notice!", wx.OK)
                dlg.ShowModal()
                dlg.Destroy()
                self.ddump_path_display.SetValue('')
                self.status_bar.SetStatusText('Failed to load ddump.')
        ddump_path_dlg.Destroy()

    def OnMapButtonClick( self, event ):
        map_path_dlg = wx.FileDialog(self, wildcard = '*.map', style=wx.OPEN)
        if map_path_dlg.ShowModal():
            # Validation key for FCM maps. This is present in all FCM maps.
            #
            mapValidationKey = 'Found "AmdTB2x16" in archive. Used in C_Platform/MCUHWAPI/Obj/FSM_REL2_2/FCM/oemflash.o\nloading' #Validation for FCM
            tempMapPath = map_path_dlg.GetPath()

            if (open(tempMapPath).read()[:95]==mapValidationKey):
                self.map_path = tempMapPath
                self.map_path_display.SetValue(self.map_path)
                self.status_bar.SetStatusText('map path loaded.')
            else:
                dlg = wx.MessageDialog( self, "Invalid or corrupted map file was loaded.\nPlease check that the loaded map is appropriate for FCM.", "Notice!", wx.OK)
                dlg.ShowModal()
                dlg.Destroy()
                self.map_path_display.SetValue('')
                self.status_bar.SetStatusText('Failed to load map file.')
        map_path_dlg.Destroy()

    def OnConvertButtonClick( self, event ):
        if not (self.ddump_path and self.map_path and self.input_display.GetValue()):
            # Execute validation of input data
            #
            dlg = wx.MessageDialog( self, "Missing ddump path, map path, or calltrace input!", "Notice!", wx.OK)
            dlg.ShowModal()
            dlg.Destroy()
            self.status_bar.SetStatusText('Missing ddump path, map path, or calltrace input!')

        #elif os.path.isfile('symbaddr.py'):
        #    # Check if symbaddr.py is present in the working directory.
        #    #
        #    dlg = wx.MessageDialog( self, "symbaddr.py missing!!!\n\nPlease put symbaddr.py in the GUI's working directory.", "Missing dependency!", wx.OK)
        #    dlg.ShowModal()
        #    dlg.Destroy()
        #    self.status_bar.SetStatusText('Missing symbaddr.py!')

        else:
            self.actual_call_stack_display.SetValue("")
            self.status_bar.SetStatusText('Converting calltrace...')

            self.input_calltrace = self.input_display.GetValue()

            if (self.input_calltrace.count('[') == self.input_calltrace.count(']<-')) and (self.input_calltrace.count('[')):
                # Initialize progress dialog
                #
                progressMax = 100
                dialog = wx.ProgressDialog("Converting...", "Time remaining", progressMax,
                style=wx.PD_CAN_ABORT | wx.PD_ELAPSED_TIME | wx.PD_REMAINING_TIME)

                keepGoing = True
                count = 0

                while keepGoing and count < progressMax:
                    # Load input calltrace to temp file
                    # dummy_header is required for symbaddr.py parsing to complete
                    #
                    dummy_header = 'Line 146: 100DF    , RhapConfFileMgr_    ,      12, 05.03 11:12:15, AaMem_CPP.cpp:153               , '

                    input_calltrace_file = file(self.input_calltrace_file_name, 'w')
                    input_calltrace_file.write(dummy_header + self.input_calltrace)
                    input_calltrace_file.close()

                    # Update progress dialog
                    #
                    count += 10
                    keepGoing = dialog.Update(count)


                    # Convert calltrace using symbaddr.py
                    #
                    proc = subprocess.call(["symbaddr.py", "CT_OSE", self.input_calltrace_file_name, self.map_path, ">", self.temp_symb_file_name],shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)


                    # Update progress dialog
                    #
                    count += 30
                    keepGoing = dialog.Update(count)


                    # Read symbolic trace which resulted from symbaddr.py
                    #
                    read_temp_symb_file = open(self.temp_symb_file_name).readlines()
                    file_to_ddump_interface = file(self.temp_file_to_ddump_interface, 'w')


                    # Search for symbolic traces and write to another temporary file
                    #
                    for entry in read_temp_symb_file:
                        M = re.findall("\[\S*?\]<-", entry)
                        if not M:
                            continue
                        for m in M:
                            tm = m.strip('[').strip(']<-')
                            file_to_ddump_interface.write(tm + '\n\n\n')

                        file_to_ddump_interface.write('\n')
                    file_to_ddump_interface.close()


                    # Update progress dialog
                    #
                    count += 10
                    keepGoing = dialog.Update(count)


                    # Execute ddump.exe to convert symbolic trace to actual calls
                    #
                    proc = subprocess.call([self.ddump_path, "-F", "<", self.temp_file_to_ddump_interface, ">", self.temp_actual_file_name], shell=True)


                    # Update progress dialog
                    #
                    count += 25
                    keepGoing = dialog.Update(count)


                    # Execute additional formating of result for rendering purposes
                    #
                    actual_string = ""
                    actual_lines = open(self.temp_actual_file_name).readlines()

                    for line in actual_lines:
                        loc_open = []
                        loc_close = []
                        loc_comma = []
                        try:
                            list_loc = line.index("[")
                        except:
                            list_loc = 10e6
                        for i in xrange(len(line)):
                            try:
                                # Format only when the arguments are too long
                                #
                                if (line.index(")") - line.index("(")) < 100:
                                    break
                            except:
                                pass
                            if i > list_loc:
                                # Limit parsing only to arguments, do not include template description inside []
                                #
                                break
                            if line[i]=="<":
                                loc_open.append(1)
                            elif line[i]==">":
                                loc_close.append(-1)
                            if (((sum(loc_open) + sum(loc_close))==0) and (line[i]==",") and (sum(loc_open)>0)):
                                # List all position of commas between separate arguments
                                #
                                loc_comma.append(i)


                        for ind in loc_comma:
                            # Perform additional manipulation for parsing purposes to be done later
                            #
                            line = line.replace(line[ind-3:ind+4], line[ind-3:ind+4].replace(',', '#'))
                        
                        # Render arguments in separate lines when the argument list is too long for easier readability
                        #
                        line = line.replace('#', ',\n\t\t\t\t')

                        actual_string += line

                    # Update progress dialog
                    #
                    count += 25
                    keepGoing = dialog.Update(count)

                # Display the result to the actual call stack display view
                #
                self.actual_call_stack_display.SetValue(actual_string)
                dialog.Destroy()
                
                # Delete all temporary files used in the process
                #
                proc = subprocess.call(["del", self.input_calltrace_file_name, self.temp_symb_file_name, self.temp_file_to_ddump_interface, self.temp_actual_file_name], shell=True)
                self.status_bar.SetStatusText('Calltrace converted successfully...')

            else:
                dlg = wx.MessageDialog( self, "Invalid input format. Accepted: [addr1]<-[addr2]<-...", "Notice!", wx.OK)
                dlg.ShowModal()
                dlg.Destroy()
                self.status_bar.SetStatusText('Invalid input format.')

    def output_splitter_windowOnIdle( self, event ):
        self.output_splitter_window.SetSashPosition( 0 )
        self.output_splitter_window.Unbind( wx.EVT_IDLE )


if __name__=="__main__":
    app = wx.App(False)
    frame = AppFrame(parent=None, title="Interactive Calltrace Conversion Tool")
    frame.Show()
    app.MainLoop()