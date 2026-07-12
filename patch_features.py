#!/usr/bin/env python3
"""
Patch Vulkan feature fields in a Mali DDK blob (libGLES_mali.so) to force
specific VkPhysicalDeviceFeatures bits to VK_TRUE.

This is independent of the GPU-ID compatibility bypass (patch_mali.py).
The VAs below were determined by disassembling vkGetPhysicalDeviceFeatures
in the 64-bit r49p1 blob. They will differ for other blob versions.
"""

import sys
import struct


def patch_features(filepath):
    print(f"[*] Opening {filepath}...")
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    # Parse ELF
    if data[:4] != b'\x7fELF':
        print("[-] Error: Not a valid ELF file")
        return False

    is_64 = data[4] == 2

    # Build VA → file offset map from PT_LOAD segments
    pt_loads = []
    if is_64:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            p_type = struct.unpack_from('<I', data, ph)[0]
            if p_type == 1:
                p_off = struct.unpack_from('<Q', data, ph + 8)[0]
                p_vaddr = struct.unpack_from('<Q', data, ph + 16)[0]
                p_fsz = struct.unpack_from('<Q', data, ph + 32)[0]
                pt_loads.append((p_off, p_vaddr, p_fsz))
        # 64-bit r49p1 feature VAs (from disassembly of vkGetPhysicalDeviceFeatures)
        feat_patches = {
            0x14b2b4: "multiDrawIndirect",
            0x149464: "fillModeNonSolid",
        }
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            p_type = struct.unpack_from('<I', data, ph)[0]
            if p_type == 1:
                p_off = struct.unpack_from('<I', data, ph + 4)[0]
                p_vaddr = struct.unpack_from('<I', data, ph + 8)[0]
                p_fsz = struct.unpack_from('<I', data, ph + 16)[0]
                pt_loads.append((p_off, p_vaddr, p_fsz))
        print("[-] 32-bit blob: feature VAs unknown for this blob; skipping.")
        return False

    def va2off(va):
        for po, pv, pf in pt_loads:
            if pv <= va < pv + pf:
                return po + (va - pv)
        return None

    patched_any = False
    for va, name in feat_patches.items():
        off = va2off(va)
        if off is None:
            print(f"[-] Warning: VA 0x{va:x} ({name}) not mapped in any PT_LOAD; skipping.")
            continue
        if off + 4 > len(data):
            print(f"[-] Warning: VA 0x{va:x} ({name}) beyond file; skipping.")
            continue
        current = struct.unpack_from('<I', data, off)[0]
        if current == 1:
            print(f"[*] {name} (VA 0x{va:x}) already VK_TRUE.")
        else:
            struct.pack_into('<I', data, off, 1)
            print(f"[+] Spoofed {name} (VA 0x{va:x}) -> VK_TRUE (was {current})")
            patched_any = True

    if not patched_any:
        print("[*] No features needed patching.")
        return True

    # Save in-place
    print(f"[*] Saving patched binary to {filepath}...")
    with open(filepath, 'wb') as f:
        f.write(data)

    print("[+] Feature patching complete.")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python patch_features.py <path_to_libGLES_mali.so>")
        sys.exit(1)
    patch_features(sys.argv[1])
