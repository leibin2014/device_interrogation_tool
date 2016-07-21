#!/usr/bin/env python
"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

import argparse
import os
import sys
import logging
import itertools
from struct import unpack
from time import sleep, time
from binascii import crc32

localdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pyOCD")
sys.path.insert(0, localdir)

localdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
sys.path.insert(0, localdir)

try:
    from intelhex import IntelHex
    intelhex_available = True
except ImportError:
    intelhex_available = False

import pyOCD
from pyOCD import __version__
from pyOCD.board import MbedBoard

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

interface = None
board = None

supported_formats = ['bin', 'hex']
supported_targets = pyOCD.target.TARGET.keys()
supported_targets.remove('cortex_m')  # No generic programming

debug_levels = LEVELS.keys()

def int_base_0(x):
    return int(x, base=0)

epi = """--chip_erase and --sector_erase can be used alone as individual commands, or they
can be used in conjunction with flashing a binary or hex file. For the former, only the erase option
will be performed. With a file, the erase options specify whether to erase the entire chip before
flashing the file, or just to erase only those sectors occupied by the file. For a standalone
sector erase, the --address and --count options are used to specify the start address of the
sector to erase and the number of sectors to erase.
"""

# Keep args in snyc with gdb_server.py when possible
parser = argparse.ArgumentParser(description='Register utility', epilog=epi)
parser.add_argument("file", nargs='?', default=None, help="Register assistant firmware")
parser.add_argument("format", nargs='?', choices=supported_formats, default=None, help="File format. Default is to use the file extension (.bin or .hex)")
parser.add_argument('--version', action='version', version=__version__)
parser.add_argument("-u", "--unique_id", action="store_true",
                    help="Read uniqueId from target device.")
parser.add_argument("-b", "--board", dest="board_id", default=None,
                    help="Connect to board by board id.  Use -l to list all connected boards.")
parser.add_argument("-c", "--cloud", dest="cloud_id", default=None,
                    help="Set cloud id.")
parser.add_argument("-k", "--key", dest="security_key", default=None,
                    help="Set security key.")
parser.add_argument("-cr", "--core_fw", dest="core_firmware", default=None,
                    help="CoreFirmware.")
parser.add_argument("-cm", "--comm_fw", dest="comm_firmware", default=None,
                    help="CommFirmware.")
parser.add_argument("-vidx", "--ver_idx", default=None, type=int_base_0,
                    help="Set firmware version index.")
parser.add_argument("-vid", "--ver_id", dest="version_id", default=None,
                    help="Set firmware version ID.")
parser.add_argument("-l", "--list", action="store_true", dest="list_all", default=False,
                    help="List all connected boards.")
parser.add_argument("-in", "--interrogation", action="store_true",
                    help="Interrogate the board.")
parser.add_argument("-d", "--debug", dest="debug_level", choices=debug_levels, default='info',
                    help="Set the level of system logging output. Supported choices are: " + ", ".join(debug_levels),
                    metavar="LEVEL")
parser.add_argument("-t", "--target", dest="target_override", choices=supported_targets, default=None,
                    help="Override target to debug.  Supported targets are: " + ", ".join(supported_targets),
                    metavar="TARGET")
parser.add_argument("-f", "--frequency", dest="frequency", default=1000000, type=int,
                    help="Set the SWD clock frequency in Hz.")
group = parser.add_mutually_exclusive_group()
group.add_argument("-ce", "--chip_erase", action="store_true", help="Use chip erase when programming.")
group.add_argument("-se", "--sector_erase", action="store_true", help="Use sector erase when programming.")
parser.add_argument("-a", "--address", default=None, type=int_base_0,
                    help="Address. Used for the sector address with sector erase, and for the address where to flash a binary.")
#parser.add_argument("-j", "--jump", default=None, type=int_base_0,
#                    help="JumpAddress. Specify which address to jump to. This is the address of Reset_Handler in ****-register.hex.")
parser.add_argument("-n", "--count", default=1, type=int_base_0,
                    help="Number of sectors to erase. Only applies to sector erase. Default is 1.")
parser.add_argument("-hp", "--hide_progress", action="store_true", help="Don't display programming progress.")
parser.add_argument("-fp", "--fast_program", action="store_true",
                    help="Use only the CRC of each page to determine if it already has the same data.")

# Notes
# -Currently "--unlock" does nothing since kinetis parts will automatically get unlocked

def setup_logging(args):
    # Set logging level
    level = LEVELS.get(args.debug_level, logging.NOTSET)
    logging.basicConfig(level=level)


def ranges(i):
    for a, b in itertools.groupby(enumerate(i), lambda (x, y): y - x):
        b = list(b)
        yield b[0][1], b[-1][1]


def print_progress(progress):
    # Reset state on 0.0
    if progress == 0.0:
        print_progress.done = False

    # print progress bar
    if not print_progress.done:
        sys.stdout.write('\r')
        i = int(progress * 20.0)
        sys.stdout.write("[%-20s] %3d%%" % ('=' * i, round(progress * 100)))
        sys.stdout.flush()

    # Finish on 1.0
    if progress >= 1.0:
        if not print_progress.done:
            print_progress.done = True
            sys.stdout.write("\n")

def print_binary(name, data):
    res = name + ': [ '
    for i in data:
        res += hex(int(i))
        res += ', '
    res = res[:-2] + ' ]'
    print(res)

def print_binary_string(name, data, comma = True):
    res = '\"' + name + '\"' + ' :' + '\"'
    for i in data:
        if (int(i) < 0x10):
            res += '0'
        res += hex(int(i))
    res += '\"'
    res = res.replace('0x','')
    if comma:
        res += ','
    print(res)

#memory address define
startAddress        = 0x20006800
writeFlagAddress    = 0x20006801
cmdAddress          = 0x20006802
lengthAddressLow    = 0x20006803
lengthAddressHigh   = 0x20006804
readFlagAddress     = 0x20006805
writeDataAddress    = 0x20006810
readDataAddress     = 0x20007810


#SCB: Vector Table Offset Register (Nordic doesn't have this register)
#SCB_VTOR_ADDRESS     = 0xE000ED08

#Vector address
BOOT_RAM_ADDRESS     = 0x20000000

#pc
register_PC          = 0


MCU_IMAGE_START      = 0xDD
MCU_IMAGE_DATA       = 0xDE
MCU_IMAGE_WRITE      = 0xDF
MCU_IMAGE_END        = 0xE0
MCU_IMAGE_UPDATE     = 0xE1
MCU_SET_CLOUDID      = 0xE2
MCU_SET_SECURITYKEY  = 0xE3
MCU_SET_VERSIONID    = 0xE4

MCU_GET_CLOUDID      = 0xE5
MCU_GET_MODULETYPE   = 0xE6
MCU_GET_VERSIONID    = 0xE7

crTotal     = 0
crProcessed = 0
cmTotal     = 0
cmProcessed = 0

def main():
    args = parser.parse_args()
    #set debug level to error
    args.debug_level = "warning"
    setup_logging(args)

    # Sanity checks before attaching to board
    if args.format == 'hex' and not intelhex_available:
        #print("Unable to program hex file")
        #print("Module 'intelhex' must be installed first")
        print_error("Unable to program hex file")
        exit()

    if args.list_all:
        all_mbeds = MbedBoard.getAllConnectedBoards(close=True, blocking=False)
        print("{")
        index = 0
        if len(all_mbeds) > 0:
            for mbed in all_mbeds:
                if index == (len(all_mbeds) - 1):
                    print ("    {\"boardId\": \"%s\"}" % (mbed.unique_id))
                else:
                    print ("    {\"boardId\": \"%s\"}," % (mbed.unique_id))
                index += 1
        print("}")

    else:
        board_selected = MbedBoard.chooseBoard(board_id=args.board_id, target_override=args.target_override,
                                               frequency=args.frequency)
        with board_selected as board:
            flash = board.flash

            progress = print_progress
            if args.hide_progress:
                progress = None
            #Hide print process
            progress = None

            has_file = args.file is not None

            chip_erase = None
            if args.chip_erase:
                chip_erase = True
            elif args.sector_erase:
                chip_erase = False

            def send_cmd(cmd, data = None):
                while (board.target.read8(writeFlagAddress) == 0x01):
                    pass
                board.target.write8(cmdAddress, cmd)
                if (data):
                    board.target.write8(lengthAddressLow,  (len(data)&0xFF))
                    board.target.write8(lengthAddressHigh, ((len(data)>>8)&0xFF))
                    board.target.writeBlockMemoryUnaligned8(writeDataAddress, data)
                else:
                    board.target.write8(lengthAddressLow,  0)
                    board.target.write8(lengthAddressHigh, 0)
                board.target.write8(writeFlagAddress, 0x01)

            def read():
                while (board.target.read8(readFlagAddress) == 0x0):
                    pass
                data = []
                size = flash.target.read8(readDataAddress + 1)
                size = (size << 8) & 0xFF00
                size += flash.target.read8(readDataAddress)
                i = 0
                while(i < size):                    
                    reg = flash.target.read8(readDataAddress + i + 2)
                    data.append(reg)
                    i = i + 1
                board.target.write8(readFlagAddress, 0x0)
                return data

            def print_error(errorString):
                print("{")
                print "\"target\": \"%s\"," % (board_selected.getInfo())
                print "\"error\": \"%s\""  % errorString
                print("}")

            if not has_file:
                if chip_erase:
                    print("Erasing chip...")
                    flash.init()
                    flash.eraseAll()
                    print("Done")
                elif args.sector_erase and args.address is not None:
                    flash.init()
                    page_addr = args.address
                    for i in range(args.count):
                        page_info = flash.getPageInfo(page_addr)
                        if not page_info:
                            break
                        # Align page address on first time through.
                        if i == 0:
                            delta = page_addr % page_info.size
                            if delta:
                                print("Warning: sector address 0x%08x is unaligned" % page_addr)
                                page_addr -= delta
                        print("Erasing sector 0x%08x" % page_addr)
                        flash.erasePage(page_addr)
                        page_addr += page_info.size
                elif args.interrogation:
                    cpuType = board_selected.getTargetType()
 
                    if cpuType == "nrf51":
                        hexFile = "nrf51_interrogation.hex"
                    elif cpuType == "stm32f103rc":
                        hexFile = "stm32f103-interrogation.hex"
                    elif cpuType == "stm32f405":
                        hexFile = "stm32f405_interrogation.hex"
                            
                    fileHex = IntelHex(hexFile)
                    addresses = fileHex.addresses()
                    addresses.sort()

                    #program register firmware to RAM(hex file)
                    data_list = list(ranges(addresses))
                    for start, end in data_list:
                        size = end - start + 1
                        data = list(fileHex.tobinarray(start=start, size=size))
                        board.target.writeBlockMemoryUnaligned8(start, data)
                    
                    #set VTOR(Nordic doesn't have this register)
                    #board.target.write32(SCB_VTOR_ADDRESS, BOOT_RAM_ADDRESS)

                    #init flag memory
                    board.target.write8(writeFlagAddress, 0x0)
                    board.target.write8(readFlagAddress, 0x0)

                    #run the register firmware, at the beginning the readFlag will be set to true to indicate HWID is readable
                    board.target.resetStopOnReset()
                    register_PC  = board.target.read32(BOOT_RAM_ADDRESS+4)
                    board.target.writeCoreRegister('pc', register_PC)
                    board.target.resume();

                    sleep(0.1)
                    
                    uniqueId = read()  

                    send_cmd(MCU_GET_MODULETYPE)  
                    moduleType = read()
                    
                    if cpuType == "nrf51":
                        moduleTypeString = "mb2000"
                    elif cpuType == "stm32f103rc":
                        if moduleType[0] == 0:
                            moduleTypeString = "mb3001" 
                        elif moduleType[0] == 1:
                            moduleTypeString = "mb2001" 
                    elif cpuType == "stm32f405":
                        if moduleType[0] == 0:
                            moduleTypeString = "mb3002" 
                        elif moduleType[0] == 1:
                            moduleTypeString = "mb2002" 
                            
                    send_cmd(MCU_GET_CLOUDID)  
                    cloudId = read()
                    
                    send_cmd(MCU_GET_VERSIONID)  
                    readFwVer = read()
                    readVerIndex = readFwVer[0]
                    readVerId = readFwVer[1:]  

                    print("{")
                    print "\"cpuType\": \"%s\"," % (cpuType)
                    print "\"moduleType\": \"%s\"," % (moduleTypeString)
                    print "\"boardId\": \"%s\"," % (board_selected.getUniqueID())
                    print_binary_string('HWID', uniqueId)
                    print "\"FirmwareIndex\": %d," % (readVerIndex)
                    print_binary_string('FirmwareId', readVerId)
                    print "\"error\": \"none\""
                    print("}")
                elif args.cloud_id and args.security_key is not None:
                    #set VTOR
                    #board.target.write32(SCB_VTOR_ADDRESS, BOOT_RAM_ADDRESS)
                    #run the register firmware, at the beginning the readFlag will be set to true to indicate HWID is readable
                    board.target.resetStopOnReset()
                    register_PC  = board.target.read32(BOOT_RAM_ADDRESS+4)                    
                    board.target.writeCoreRegister('pc', register_PC)
                    board.target.resume();

                    sleep(0.1)
                    uniqueId = read()
                    cloudId =  [ord(x) for x in list(args.cloud_id)]
                    #cloudId_hex = [hex(i) for i in cloudId]
                    #print cloudId_hex
                    #print_binary('CloudId', cloudId)
                    cloudIdCrc = crc32(bytearray(cloudId), 0xFFFFFFFF)  & 0xFFFFFFFF
                    cloudId.append(cloudIdCrc & 0xFF)
                    cloudId.append((cloudIdCrc>>8) & 0xFF)
                    cloudId.append((cloudIdCrc>>16) & 0xFF)
                    cloudId.append((cloudIdCrc>>24) & 0xFF)
                    send_cmd(MCU_SET_CLOUDID, cloudId)
                    cloudIdRead = read()
                    cloudIdRead = cloudIdRead[:8]
                    cloudIdRead = [chr(x) for x in cloudIdRead]

                    #write security key: 78,99,56,....
                    securityKey = args.security_key.replace('0x','').split(',')
                    securityKey =  [int(x, 16) for x in list(securityKey)]
                    send_cmd(MCU_SET_SECURITYKEY, securityKey)
                    securityKeyRead = read()

                    print("{")
                    print "\"target\": \"%s\"," % (board_selected.getInfo())
                    print_binary_string('HWID', uniqueId)
                    print "\"CloudId\": \"%s\"," % (''.join(cloudIdRead))
                    print_binary_string('SecurityKey', securityKeyRead)
                    print "\"error\": \"none\""
                    print("}")
                elif args.core_firmware and args.comm_firmware is not None:
                    #board.target.write32(SCB_VTOR_ADDRESS, BOOT_RAM_ADDRESS)
                    #run the register firmware, at the beginning the readFlag will be set to true to indicate HWID is readable
                    board.target.resetStopOnReset()
                    register_PC  = board.target.read32(BOOT_RAM_ADDRESS+4)
                    board.target.writeCoreRegister('pc', register_PC)
                    board.target.resume();

                    sleep(0.1)
                    uniqueId = read()

                    writeResult = []

                    def update_fw(image, fwType):
                        global crTotal
                        global crProcessed
                        global cmTotal
                        global cmProcessed
                        with open(image, "rb") as f:
                            fwImage = f.read()
                        fwImage = unpack(str(len(fwImage)) + 'B', fwImage)
                        while (board.target.read8(writeFlagAddress) == 0x01):
                            pass
                        imageSize = len(fwImage)
                        crc32Value = crc32(bytearray(fwImage), 0xFFFFFFFF)  & 0xFFFFFFFF
                        #print("image size is: 0x%x" % imageSize)
                        #print("crc value is: 0x%x" % crc32Value)

                        startData = []
                        startData.append(fwType)
                        startData.append((imageSize>>24) & 0xFF)
                        startData.append((imageSize>>16) & 0xFF)
                        startData.append((imageSize>>8) & 0xFF)
                        startData.append(imageSize & 0xFF)
                        startData.append((crc32Value>>24) & 0xFF)
                        startData.append((crc32Value>>16) & 0xFF)
                        startData.append((crc32Value>>8) & 0xFF)
                        startData.append(crc32Value & 0xFF)
                        send_cmd(MCU_IMAGE_START, startData)

                        streamDataSize  = 2048
                        packages        = imageSize / streamDataSize
                        remains         = imageSize % streamDataSize
                        num = 0
                        while (packages != num):
                            #MESHTALK_CMD_MCU_IMAGE_DATA
                            send_cmd(MCU_IMAGE_DATA, fwImage[(num*streamDataSize):(num*streamDataSize + streamDataSize)])
                            num = num + 1
                            if(fwType == 0):
                                if(num == packages):
                                    crProcessed = crTotal
                                else:
                                    crProcessed = num * 2048
                            else:
                                if(num == packages):
                                    cmProcessed = cmTotal
                                else:
                                    cmProcessed = num * 2048
                            print("{")
                            print("    \"cr\":")
                            print("    {")
                            print "    \"total\"    : %d," % (crTotal)
                            print "    \"processed\": %d" % (crProcessed)
                            print("    },")
                            print("    \"cm\":")
                            print("    {")
                            print "    \"total\"    : %d," % (cmTotal)
                            print "    \"processed\": %d" % (cmProcessed)
                            print("    }")
                            print("}")

                        if (remains != 0):
                            #MESHTALK_CMD_MCU_IMAGE_DATA
                            send_cmd(MCU_IMAGE_DATA, fwImage[(num*streamDataSize):(num*streamDataSize + remains)])

                        #MESHTALK_CMD_MCU_IMAGE_SEND_END
                        send_cmd(MCU_IMAGE_END);

                    global crTotal
                    global crProcessed
                    global cmTotal
                    global cmProcessed
                    with open(args.core_firmware, "rb") as f:
                        fwImage = f.read()
                    fwImage = unpack(str(len(fwImage)) + 'B', fwImage)
                    crTotal = len(fwImage)
                    crProcessed = 0

                    with open(args.comm_firmware, "rb") as f:
                        fwImage = f.read()
                    fwImage = unpack(str(len(fwImage)) + 'B', fwImage)
                    cmTotal = len(fwImage)
                    cmProcessed = 0

                    #update CoreFW
                    update_fw(args.core_firmware, 0)
                    CoreFWWriteResult = read()
                    #update CommFW
                    update_fw(args.comm_firmware, 1)
                    CommFWWriteResult = read()


                    fwVer = []
                    if args.ver_idx is not None:
                        fwVer.append(args.ver_idx)
                    else:
                        fwVer.append(0)

                    if args.version_id is not None:
                        verId = args.version_id.replace('0x','').split(',')
                        verId =  [int(x, 16) for x in list(verId)]
                        fwVer += verId
                    else:
                        fwVer += [0, 0, 0, 0, 0, 0, 0, 0]

                    send_cmd(MCU_SET_VERSIONID, fwVer)
                    readFwVer = read()
                    readVerIndex = readFwVer[0]
                    readVerId = readFwVer[1:]


                    #MESHTALK_CMD_MCU_IMAGE_EN_UPDATE
                    imagetype = [0x03]
                    send_cmd(MCU_IMAGE_UPDATE, imagetype)
                    updateResult = read()
                    if CoreFWWriteResult[0] == 1 and CommFWWriteResult[0] == 1 and updateResult[0] == 1:
                        print("{")
                        print "\"target\": \"%s\"," % (board_selected.getInfo())
                        print_binary_string('HWID', uniqueId)
                        print "\"FirmwareIndex\": %d," % (readVerIndex)
                        print_binary_string('FirmwareId', readVerId)
                        print "\"error\": \"none\""
                        print("}")
                        
                        board.target.reset()
                    else:
                        print_error("Write image error!")
                else:
                    #print("No operation performed")
                    print_error("No operation performed")
                return

            # If no format provided, use the file's extension.
            if not args.format:
                args.format = os.path.splitext(args.file)[1][1:]

            # Intel hex file format
            if args.format == 'hex' is not None:
                fileHex = IntelHex(args.file)
                addresses = fileHex.addresses()
                addresses.sort()
                
                if(addresses[0] >= 0x20000000):
                    #program register firmware to RAM(hex file)
                    data_list = list(ranges(addresses))
                    for start, end in data_list:
                        size = end - start + 1
                        data = list(fileHex.tobinarray(start=start, size=size))
                        board.target.writeBlockMemoryUnaligned8(start, data)               
                else:
                    flash_builder = flash.getFlashBuilder()

                    data_list = list(ranges(addresses))
                    for start, end in data_list:
                        size = end - start + 1
                        data = list(fileHex.tobinarray(start=start, size=size))
                        flash_builder.addData(start, data)

                    #program register firmware to flash(hex file)
                    flash_builder.program(chip_erase=chip_erase, progress_cb=progress, fast_verify=args.fast_program)

            else:
                #print("Unknown file format '%s'" % args.format)
                errorString = "Unknown file format " + args.format
                print_error(errorString)

            #readout unique id
            if args.unique_id:
                #set VTOR
                #board.target.write32(SCB_VTOR_ADDRESS, BOOT_RAM_ADDRESS)

                #init flag memory
                board.target.write8(writeFlagAddress, 0x0)
                board.target.write8(readFlagAddress, 0x0)

                #run the register firmware, at the beginning the readFlag will be set to true to indicate HWID is readable
                board.target.resetStopOnReset()
                register_PC  = board.target.read32(BOOT_RAM_ADDRESS+4)
                board.target.writeCoreRegister('pc', register_PC)
                board.target.resume();

                sleep(0.1)

                uniqueId = read()

                print("{")
                print "\"target\": \"%s\"," % (board_selected.getInfo())
                print_binary_string('HWID', uniqueId)
                print "\"error\": \"none\""
                print("}")
            else:
                print("{")
                print "\"target\": \"%s\"," % (board_selected.getInfo())
                print "\"error\": \"none\""
                print("}")

if __name__ == '__main__':
    main()
