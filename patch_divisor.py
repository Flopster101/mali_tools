#!/usr/bin/env python3
"""
Rename VK_KHR_vertex_attribute_divisor → VK_EXT_vertex_attribute_divisor
in a Mali DDK blob (libGLES_mali.so).

Both strings are exactly 28 bytes, so an in-place byte swap renames the
extension consistently in the enumeration list AND the dispatch table.
"""

import sys


def patch_divisor(filepath):
    print(f"[*] Opening {filepath}...")
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    old_ext = b"VK_KHR_vertex_attribute_divisor"
    new_ext = b"VK_EXT_vertex_attribute_divisor"

    cnt = data.count(old_ext)
    if cnt == 0:
        if data.count(new_ext) > 0:
            print(f"[*] Extension already renamed ({data.count(new_ext)} occurrence(s) of VK_EXT_...).")
        else:
            print("[-] Warning: neither VK_KHR_ nor VK_EXT_vertex_attribute_divisor found; skipping rename.")
        return True

    data = bytearray(data.replace(old_ext, new_ext))
    print(f"[+] Renamed {cnt} occurrence(s) of VK_KHR_vertex_attribute_divisor -> VK_EXT_vertex_attribute_divisor")

    # Save in-place
    print(f"[*] Saving patched binary to {filepath}...")
    with open(filepath, 'wb') as f:
        f.write(data)

    print("[+] Divisor rename complete.")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python patch_divisor.py <path_to_libGLES_mali.so>")
        sys.exit(1)
    patch_divisor(sys.argv[1])
