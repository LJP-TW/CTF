import idc
import ida_kernwin

filename = ida_kernwin.ask_file(1, "*.bin", "Output file name")
address = 0x141070240

with open(filename, "wb") as out:
    while True:
        data = idc.get_bytes(address, 1)
        if data == b'\0':
            break    
        out.write(data)
        address += 1
