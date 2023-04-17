import argparse
import logging
import os
import struct
from typing import Optional
import pefile

def find_offset(dll: str) -> Optional[int]:
    ''' Feature settings are stored as a structure of char*, bool*
    The address of the configuration directly follows this string '''
    pe_hndl = pefile.PE(dll, fast_load=True)

    # Find the rdata section
    for section in pe_hndl.sections:
        if section.Name.rstrip(b'\0') == b'.rdata':
            rdata = section

    with open(dll, 'rb') as file_hndl:
        file_hndl.seek(rdata.PointerToRawData, os.SEEK_SET)
        data = file_hndl.read(rdata.SizeOfRawData)
        string_sctn_offset = data.find(b'MojoJS\0')
        if string_sctn_offset == -1:
            logging.critical('Unable to find MojoJS string')
            return None
        string_offset = rdata.PointerToRawData + string_sctn_offset

        string_rva = pe_hndl.get_rva_from_offset(string_offset)
        print(f'RVA of MojoJS string:  {hex(string_rva)}')
        string_va = pe_hndl.OPTIONAL_HEADER.ImageBase + string_rva
        print(f'VA of MojoJS String:   {hex(string_va)}')
        raw_string_pointer = struct.pack('Q', string_va)

        string_pointer_sectn_offset = data.find(raw_string_pointer)
        string_pointer_offset = rdata.PointerToRawData + string_pointer_sectn_offset
        string_pointer_offset_rva = pe_hndl.get_rva_from_offset(string_pointer_offset)
        string_pointer_offset_va = string_pointer_offset_rva + pe_hndl.OPTIONAL_HEADER.ImageBase
        print(f'Ptr to MojoJS string:  {hex(string_pointer_offset_va)}')

        # The boolean follows this offset in memory
        offset_to_bool_ptr = string_pointer_sectn_offset + 8
        bool_ptr_bytes = data[offset_to_bool_ptr:offset_to_bool_ptr+8]
        bool_ptr = struct.unpack('Q', bool_ptr_bytes)[0]
        print(f'VA of mojojs_enabled_: {hex(bool_ptr)}')
        bool_offset_rva = bool_ptr - pe_hndl.OPTIONAL_HEADER.ImageBase
        raw_bool_offset = pe_hndl.get_offset_from_rva(bool_offset_rva)
        print(f'Offset from img base:  {hex(raw_bool_offset)}')

        return bool_ptr

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find the address of the mojojs_enabled_ flag.')
    parser.add_argument('dll', help='chrome.dll (or equivalent) file to search')
    args = parser.parse_args()

    offset = find_offset(args.dll)
