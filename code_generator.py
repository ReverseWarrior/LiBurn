import donut

def generate_header(input_file: str, output_header: str):
    asm = donut.create(file=input_file)

    print(f"[+] Assembly code size: {len(asm)} bytes")

    with open(output_header, 'w') as f:
        f.write('#pragma once\n\n')
        f.write('unsigned char shellcode[] = {\n    ')
        for i, b in enumerate(asm):
            f.write(f'0x{b:02X}, ')
            if (i + 1) % 16 == 0:
                f.write('\n    ')
        f.write('\n};\n')
        f.write(f'unsigned int shellcodeSize = {len(asm)};\n')

    print(f"[+] Header file written to {output_header}")

if __name__ == '__main__':
    # Update this path to your EXE
    input_exe = "build\\Release\\LiBurn-Payload.exe"
    output_header = "LiBurn\\shellcode.hpp"
    generate_header(input_exe, output_header)
