import sys
import os
import struct


def patched_path(filepath):
    """Sibling path carrying the _patched suffix, preserving the .so.* tail."""
    root, ext = os.path.splitext(filepath)
    if root.endswith('_patched'):
        return filepath
    return f"{root}_patched{ext}"


def patch_mali_ddk(filepath, outpath=None):
    print(f"[*] Opening {filepath}...")
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    # 1. Parse ELF header to locate PT_LOAD segments and map VAs
    elf_magic = data[:4]
    if elf_magic != b'\x7fELF':
        print("[-] Error: Not a valid ELF file")
        return False
    
    is_64 = data[4] == 2
    is_32 = data[4] == 1
    
    if not is_64 and not is_32:
        print("[-] Error: Unsupported ELF class")
        return False

    pt_loads = []
    if is_64:
        # ELF64
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]

        for i in range(e_phnum):
            ph_offset = e_phoff + i * e_phentsize
            p_type = struct.unpack_from('<I', data, ph_offset)[0]
            if p_type == 1: # PT_LOAD
                p_flags = struct.unpack_from('<I', data, ph_offset + 4)[0]
                p_offset = struct.unpack_from('<Q', data, ph_offset + 8)[0]
                p_vaddr = struct.unpack_from('<Q', data, ph_offset + 16)[0]
                p_filesz = struct.unpack_from('<Q', data, ph_offset + 32)[0]
                pt_loads.append({
                    'offset': p_offset,
                    'vaddr': p_vaddr,
                    'filesz': p_filesz,
                    'flags': p_flags
                })
    else:
        # ELF32
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]

        for i in range(e_phnum):
            ph_offset = e_phoff + i * e_phentsize
            p_type = struct.unpack_from('<I', data, ph_offset)[0]
            if p_type == 1: # PT_LOAD
                p_offset = struct.unpack_from('<I', data, ph_offset + 4)[0]
                p_vaddr = struct.unpack_from('<I', data, ph_offset + 8)[0]
                p_filesz = struct.unpack_from('<I', data, ph_offset + 16)[0]
                p_flags = struct.unpack_from('<I', data, ph_offset + 24)[0]
                pt_loads.append({
                    'offset': p_offset,
                    'vaddr': p_vaddr,
                    'filesz': p_filesz,
                    'flags': p_flags
                })

    def va_to_offset(va):
        for segment in pt_loads:
            if segment['vaddr'] <= va < segment['vaddr'] + segment['filesz']:
                return segment['offset'] + (va - segment['vaddr'])
        return None

    def offset_to_va(offset):
        for segment in pt_loads:
            if segment['offset'] <= offset < segment['offset'] + segment['filesz']:
                return segment['vaddr'] + (offset - segment['offset'])
        return None

    # 2. Search for the error string
    search_str = b"is not compatible with this Mali GPU device"
    sub_offset = data.find(search_str)
    if sub_offset == -1:
        print("[-] Error: Could not find the compatibility mismatch error string in the binary.")
        return False
    
    # Find the start of the null-terminated string by scanning backwards
    str_offset = sub_offset
    while str_offset > 0 and data[str_offset - 1] != 0:
        str_offset -= 1
        
    str_va = offset_to_va(str_offset)
    print(f"[+] Found error string start at offset 0x{str_offset:x} (VA 0x{str_va:x})")

    # 3. Scan executable segments for code referencing the string
    ref_offset = None
    mode = None

    if is_64:
        mode = "arm64"
        for segment in pt_loads:
            if not (segment['flags'] & 1): # PF_X = 1
                continue
            start_offset = segment['offset']
            end_offset = start_offset + segment['filesz']
            for offset in range(start_offset, end_offset - 8, 4):
                inst1 = struct.unpack_from('<I', data, offset)[0]
                # Check for ADRP (op=1, bits 31=1, 29-30=immlo, 24-28=10000)
                if (inst1 & 0x9f000000) == 0x90000000:
                    rd = inst1 & 0x1f
                    immlo = (inst1 >> 29) & 3
                    immhi = (inst1 >> 5) & 0x7ffff
                    imm21 = (immhi << 2) | immlo
                    if imm21 & 0x100000:
                        imm21 -= 0x200000
                    pc = offset_to_va(offset)
                    adrp_target_page = (pc & ~0xfff) + imm21 * 4096
                    
                    inst2 = struct.unpack_from('<I', data, offset + 4)[0]
                    if (inst2 & 0xffc00000) == 0x91000000:
                        rn2 = (inst2 >> 5) & 0x1f
                        rd2 = inst2 & 0x1f
                        if rn2 == rd and rd2 == rd:
                            imm12 = (inst2 >> 10) & 0xfff
                            target_va = adrp_target_page + imm12
                            if target_va == str_va:
                                print(f"[+] Found reference to error string at offset 0x{offset:x} (VA 0x{pc:x})")
                                ref_offset = offset
                                break
            if ref_offset is not None:
                break
    else:
        # ELF32 - scan for both Thumb and ARM mode references
        # Let's try Thumb first as it's the most common
        print("[*] Scanning executable segments for Thumb mode string references...")
        for segment in pt_loads:
            if not (segment['flags'] & 1):
                continue
            start_offset = segment['offset']
            end_offset = start_offset + segment['filesz']
            for offset in range(start_offset, end_offset - 6, 2):
                inst = struct.unpack_from('<H', data, offset)[0]
                # Check for Thumb ldr rd, [pc, #imm] -> 0x4800 | (rd << 8) | imm8
                if (inst & 0xf800) == 0x4800:
                    rd = (inst >> 8) & 7
                    imm8 = inst & 0xff
                    pc_ldr = (offset_to_va(offset) & ~3) + 4
                    lit_pool_va = pc_ldr + imm8 * 4
                    lit_pool_offset = va_to_offset(lit_pool_va)
                    if lit_pool_offset is not None and lit_pool_offset + 4 <= len(data):
                        val = struct.unpack_from('<I', data, lit_pool_offset)[0]
                        # Check for add rd, pc within 12 bytes (handles compiler scheduling gaps)
                        for add_offset in range(offset + 2, offset + 14, 2):
                            if add_offset + 2 > end_offset:
                                break
                            add_inst = struct.unpack_from('<H', data, add_offset)[0]
                            if add_inst == 0x4478 + rd:
                                pc_add = offset_to_va(add_offset) + 4
                                target_va = (val + pc_add) & 0xffffffff
                                if target_va == str_va:
                                    print(f"[+] Found Thumb reference to error string at offset 0x{offset:x} (VA 0x{offset_to_va(offset):x})")
                                    ref_offset = offset
                                    mode = "thumb"
                                    break
                        if ref_offset is not None:
                            break
            if ref_offset is not None:
                break

        # If Thumb search failed, try ARM mode
        if ref_offset is None:
            print("[*] Scanning executable segments for ARM mode string references...")
            for segment in pt_loads:
                if not (segment['flags'] & 1):
                    continue
                start_offset = segment['offset']
                end_offset = start_offset + segment['filesz']
                for offset in range(start_offset, end_offset - 8, 4):
                    inst = struct.unpack_from('<I', data, offset)[0]
                    # Check for ARM ldr rd, [pc, #imm] -> 0xe51f0000 / 0xe59f0000
                    if (inst & 0xff7f0000) == 0xe59f0000 or (inst & 0xff7f0000) == 0xe51f0000:
                        rd = (inst >> 12) & 0xf
                        imm12 = inst & 0xfff
                        pc_ldr = offset_to_va(offset) + 8
                        is_positive = (inst & 0x00800000) != 0
                        lit_pool_va = (pc_ldr + imm12) if is_positive else (pc_ldr - imm12)
                        lit_pool_offset = va_to_offset(lit_pool_va)
                        if lit_pool_offset is not None and lit_pool_offset + 4 <= len(data):
                            val = struct.unpack_from('<I', data, lit_pool_offset)[0]
                            # Check for add rd, rd, pc or add rd, pc, rd at offset + 4
                            add_inst = struct.unpack_from('<I', data, offset + 4)[0]
                            is_add = (add_inst == (0xe080000f | (rd << 16) | (rd << 12))) or \
                                     (add_inst == (0xe08f0000 | (rd << 12) | rd))
                            if is_add:
                                pc_add = offset_to_va(offset + 4) + 8
                                target_va = (val + pc_add) & 0xffffffff
                                if target_va == str_va:
                                    print(f"[+] Found ARM reference to error string at offset 0x{offset:x} (VA 0x{offset_to_va(offset):x})")
                                    ref_offset = offset
                                    mode = "arm"
                                    break
                if ref_offset is not None:
                    break

    if ref_offset is None:
        print("[-] Error: Could not find any code reference to the compatibility error string.")
        return False

    # 4. Find the start of the function by scanning backwards
    func_start_offset = None

    if mode == "arm64":
        # Scan backwards for a previous ret or prologue
        for offset in range(ref_offset - 4, ref_offset - 0x1000, -4):
            inst = struct.unpack_from('<I', data, offset)[0]
            if inst == 0xd65f03c0: # ret
                # A bypassed entry is `mov w0,#1; ret`, so the scan finds the
                # stub's own ret one word in. Step back so re-runs resolve to
                # the entry instead of the prologue that follows it.
                if data[offset-4:offset] == b'\x20\x00\x80\x52':
                    func_start_offset = offset - 4
                    break
                entry_offset = offset + 4
                while entry_offset < ref_offset:
                    first_inst = struct.unpack_from('<I', data, entry_offset)[0]
                    if first_inst != 0 and first_inst != 0xd503201f:
                        func_start_offset = entry_offset
                        break
                    entry_offset += 4
                break

        if func_start_offset is None:
            print("[-] Warning: Ret-based scan failed. Trying prologue-based backwards scan...")
            for offset in range(ref_offset - 4, ref_offset - 0x1000, -4):
                inst = struct.unpack_from('<I', data, offset)[0]
                if (inst & 0xffc003ff) == 0xd10003ff or (inst & 0xffc07fff) == 0xa9807bfd:
                    func_start_offset = offset
                    break

    elif mode == "thumb":
        # Prioritize prologue push
        for offset in range(ref_offset - 2, ref_offset - 0x1000, -2):
            if offset < 0:
                break
            # A bypassed entry is `movs r0,#1; bx lr` and no longer looks like
            # a push, so match the stub first and stop there for re-runs.
            if data[offset:offset+4] == b'\x01\x20\x70\x47':
                func_start_offset = offset
                break
            inst = struct.unpack_from('<H', data, offset)[0]
            # 16-bit push {..., lr} -> (inst & 0xff00) == 0xb500
            if (inst & 0xff00) == 0xb500:
                func_start_offset = offset
                break
            # 32-bit push.w {..., lr} -> inst == 0xe92d and (next_inst & 0x4000) != 0
            if inst == 0xe92d:
                next_inst = struct.unpack_from('<H', data, offset + 2)[0]
                if (next_inst & 0x4000) != 0:
                    func_start_offset = offset
                    break

        if func_start_offset is None:
            print("[-] Warning: Prologue push-based scan failed. Trying end-of-previous-function scan...")
            for offset in range(ref_offset - 2, ref_offset - 0x1000, -2):
                if offset < 0:
                    break
                inst = struct.unpack_from('<H', data, offset)[0]
                # A bypassed entry is `movs r0,#1; bx lr`, so this scan finds
                # the stub's own bx lr. Step back to the entry for re-runs.
                if inst == 0x4770 and data[offset-2:offset] == b'\x01\x20':
                    func_start_offset = offset - 2
                    break
                if inst == 0x4770 or (inst & 0xff00) == 0xbd00:
                    entry_offset = offset + 2
                    while entry_offset < ref_offset:
                        first_inst = struct.unpack_from('<H', data, entry_offset)[0]
                        # Recognize 0xd4d4 (trap/padding) and standard padding
                        if first_inst != 0 and first_inst != 0xbf00 and first_inst != 0x46c0 and first_inst != 0xd4d4:
                            func_start_offset = entry_offset
                            break
                        entry_offset += 2
                    break

    elif mode == "arm":
        # Prioritize prologue push (stmfd sp!, {..., lr}) -> (inst & 0xffff4000) == 0xe92d4000
        # or sub sp, sp, #... -> (inst & 0xfffff000) == 0xe24dd000
        for offset in range(ref_offset - 4, ref_offset - 0x1000, -4):
            if offset < 0:
                break
            inst = struct.unpack_from('<I', data, offset)[0]
            if (inst & 0xffff4000) == 0xe92d4000 or (inst & 0xfffff000) == 0xe24dd000:
                func_start_offset = offset
                break

        if func_start_offset is None:
            print("[-] Warning: Prologue scan failed. Trying end-of-previous-function scan...")
            for offset in range(ref_offset - 4, ref_offset - 0x1000, -4):
                if offset < 0:
                    break
                inst = struct.unpack_from('<I', data, offset)[0]
                if inst == 0xe12fff1e or (inst & 0xffff8000) == 0xe8bd8000:
                    entry_offset = offset + 4
                    while entry_offset < ref_offset:
                        first_inst = struct.unpack_from('<I', data, entry_offset)[0]
                        if first_inst != 0 and first_inst != 0xe1a00000:
                            func_start_offset = entry_offset
                            break
                        entry_offset += 4
                    break

    # 5. Patch the function start to return true (1) immediately
    if mode == "arm64":
        # mov w0, #1 -> 0x52800020, ret -> 0xd65f03c0
        patch_bytes = b'\x20\x00\x80\x52\xc0\x03\x5f\xd6'
    elif mode == "thumb":
        # movs r0, #1 -> 0x2001, bx lr -> 0x4770
        patch_bytes = b'\x01\x20\x70\x47'
    elif mode == "arm":
        # mov r0, #1 -> 0xe3a00001, bx lr -> 0xe12fff1e
        patch_bytes = b'\x01\x00\xa0\xe3\x1e\xff\x2f\xe1'

    if func_start_offset is None:
        print("[-] Error: Could not determine the function start address.")
        return False

    func_start_va = offset_to_va(func_start_offset)
    print(f"[+] Found function start at offset 0x{func_start_offset:x} (VA 0x{func_start_va:x}) [mode: {mode}]")

    original_bytes = data[func_start_offset:func_start_offset+len(patch_bytes)]
    dest = outpath or patched_path(filepath)

    if original_bytes == patch_bytes:
        print(f"[=] Already patched at 0x{func_start_offset:x}; nothing to do.")
        print(f"[*] Saving patched binary to {dest}...")
        with open(dest, 'wb') as f:
            f.write(data)
        return True

    print(f"[+] Patching {len(patch_bytes)} bytes at offset 0x{func_start_offset:x}...")
    print(f"    Original bytes: {original_bytes.hex()}")
    print(f"    New bytes:      {patch_bytes.hex()}")

    data[func_start_offset:func_start_offset+len(patch_bytes)] = patch_bytes
    print("[+] GPU compatibility check bypassed.")

    print(f"[*] Saving patched binary to {dest}...")
    with open(dest, 'wb') as f:
        f.write(data)

    print("[+] Patching complete! GPU check bypassed.")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python patch_mali.py <path_to_libGLES_mali.so> [output_path]")
        print("Writes <name>_patched.so alongside the input unless output_path is given.")
        sys.exit(1)
    out = sys.argv[2] if len(sys.argv) > 2 else None
    sys.exit(0 if patch_mali_ddk(sys.argv[1], out) else 1)
