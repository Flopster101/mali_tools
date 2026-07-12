#!/usr/bin/env python3
import os
import sys
import struct

# ANSI Color Codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_success(msg):
    print(f"{GREEN}[+]{RESET} {msg}")

def print_warn(msg):
    print(f"{YELLOW}[!]{RESET} {msg}")

def print_error(msg):
    print(f"{RED}[-]{RESET} {msg}")

def print_info(msg):
    print(f"{CYAN}[*]{RESET} {msg}")

# Core patch function (Direct ELF .dynstr modification)
def patch_elf_dependency(filepath, old_name="libc++.so", new_name="libcxx.so"):
    if len(old_name) != len(new_name):
        print_error(f"Internal Error: String lengths must match exactly ({len(old_name)} vs {len(new_name)})")
        return False
        
    try:
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())
            
        old_bytes = old_name.encode('utf-8') + b'\x00'
        new_bytes = new_name.encode('utf-8') + b'\x00'
        
        if old_bytes in data:
            occurrences = data.count(old_bytes)
            # Patch in-place
            idx = 0
            while True:
                idx = data.find(old_bytes, idx)
                if idx == -1:
                    break
                data[idx:idx+len(new_bytes)] = new_bytes
                idx += len(new_bytes)
                
            with open(filepath, 'wb') as f:
                f.write(data)
            return True, occurrences
        return False, 0
    except Exception as e:
        return None, str(e)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 patch_dependencies.py <target_directory_or_magisk_module>")
        sys.exit(1)
        
    input_path = os.path.abspath(sys.argv[1])
    
    if not os.path.exists(input_path):
        print_error(f"Directory does not exist: {input_path}")
        sys.exit(1)
        
    # Resolve the base vendor directory
    vendor_dir = None
    candidates = [
        os.path.join(input_path, "system", "vendor"),
        os.path.join(input_path, "vendor"),
        input_path
    ]
    
    for cand in candidates:
        if os.path.exists(os.path.join(cand, "lib")) or os.path.exists(os.path.join(cand, "lib64")):
            vendor_dir = cand
            break
            
    if not vendor_dir:
        print_error("Could not locate 'vendor/lib' or 'vendor/lib64' structure in target folder.")
        sys.exit(1)
        
    print_info(f"Target vendor directory resolved to: {vendor_dir}")
    
    lib32_dir = os.path.join(vendor_dir, "lib")
    lib64_dir = os.path.join(vendor_dir, "lib64")
    
    has_32 = os.path.exists(lib32_dir)
    has_64 = os.path.exists(lib64_dir)
    
    if not has_32 and not has_64:
        print_error("No 'lib' or 'lib64' directory found inside the resolved vendor path.")
        sys.exit(1)
        
    # Standard dependencies we expect to find next to Mali driver
    expected_deps = [
        "android.hardware.graphics.allocator-V2-ndk.so",
        "libgralloctypes.so",
        "android.hardware.graphics.mapper@4.0.so"
    ]
    
    optional_deps = [
        "android.hardware.graphics.common-V5-ndk.so",
        "android.hardware.graphics.common-V7-ndk.so",
        "libdrm.so",
        "libdmabufheap.so"
    ]
    
    # 1. Verification phase (Fail-safe checks & Arch identification)
    archs_to_process = []
    
    if has_32:
        mali_32 = os.path.join(lib32_dir, "egl", "libGLES_mali.so")
        has_mali_32 = os.path.exists(mali_32)
        
        found_deps_32 = [d for d in expected_deps if os.path.exists(os.path.join(lib32_dir, d))]
        found_opt_32 = [d for d in optional_deps if os.path.exists(os.path.join(lib32_dir, d))]
        
        if has_mali_32:
            print_info("Found 32-bit Mali driver blob.")
            archs_to_process.append(("32-bit", lib32_dir))
            if len(found_deps_32) < len(expected_deps):
                missing = set(expected_deps) - set(found_deps_32)
                print_warn(f"32-bit Mali driver is present but dependencies are missing: {', '.join(missing)}")
                print_warn("32-bit Vulkan/OpenGL loading may fail in 32-bit applications.")
        elif (len(found_deps_32) + len(found_opt_32)) > 0:
            print_warn("32-bit dependencies are present, but 32-bit Mali driver is missing.")
            archs_to_process.append(("32-bit", lib32_dir))
            
    if has_64:
        mali_64 = os.path.join(lib64_dir, "egl", "libGLES_mali.so")
        has_mali_64 = os.path.exists(mali_64)
        
        found_deps_64 = [d for d in expected_deps if os.path.exists(os.path.join(lib64_dir, d))]
        found_opt_64 = [d for d in optional_deps if os.path.exists(os.path.join(lib64_dir, d))]
        
        if has_mali_64:
            print_info("Found 64-bit Mali driver blob.")
            archs_to_process.append(("64-bit", lib64_dir))
            if len(found_deps_64) < len(expected_deps):
                missing = set(expected_deps) - set(found_deps_64)
                print_warn(f"64-bit Mali driver is present but dependencies are missing: {', '.join(missing)}")
                print_warn("64-bit OpenGL/SurfaceComposer will fail to load (will bootloop).")
        elif (len(found_deps_64) + len(found_opt_64)) > 0:
            print_warn("64-bit dependencies are present, but 64-bit Mali driver is missing.")
            archs_to_process.append(("64-bit", lib64_dir))

    if not archs_to_process:
        print_error("No Mali drivers or dependency shims found to patch.")
        sys.exit(1)
        
    # 2. Execution phase (Shimming libraries)
    print_info("Starting C++ STL dependency redirection (libc++.so -> libcxx.so)...")
    
    total_patched = 0
    total_skipped = 0
    total_failed = 0
    
    for arch_name, path in archs_to_process:
        print_info(f"Processing {arch_name} libraries in {path}...")
        
        # Check if libc++.so exists in this directory and needs renaming/patching
        libcplus_path = os.path.join(path, "libc++.so")
        libcxx_path = os.path.join(path, "libcxx.so")
        
        if os.path.exists(libcplus_path):
            print_info(f"Found clean libc++.so in {arch_name} folder. Renaming to libcxx.so and patching SONAME...")
            res, detail = patch_elf_dependency(libcplus_path, old_name="libc++.so", new_name="libcxx.so")
            if res is True:
                print_success(f"Patched SONAME inside: {os.path.basename(libcplus_path)}")
                total_patched += 1
            elif res is False:
                total_skipped += 1
            else:
                print_error(f"Failed to patch SONAME in libc++.so: {detail}")
                total_failed += 1
                
            try:
                if os.path.exists(libcxx_path):
                    os.remove(libcxx_path)
                os.rename(libcplus_path, libcxx_path)
                print_success(f"Renamed {os.path.basename(libcplus_path)} -> libcxx.so")
            except Exception as e:
                print_error(f"Failed to rename libc++.so to libcxx.so: {e}")
                total_failed += 1

        # Gather all .so files in the directory and egl/ subdirectory
        so_files = []
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".so") and file != "libcxx.so" and file != "libc++.so":
                    so_files.append(os.path.join(root, file))
                    
        for filepath in so_files:
            rel_name = os.path.relpath(filepath, vendor_dir)
            res, detail = patch_elf_dependency(filepath)
            
            if res is True:
                print_success(f"Patched dependency in: {rel_name} ({detail} ref(s))")
                total_patched += 1
            elif res is False:
                total_skipped += 1
            else:
                print_error(f"Failed to patch {rel_name}: {detail}")
                total_failed += 1
                
    # 3. Final summary
    print("\n" + "="*40 + "\n")
    print_info("Execution Summary:")
    print_success(f"Successfully patched: {total_patched} file(s)")
    print_info(f"Skipped (already patched or no reference): {total_skipped} file(s)")
    if total_failed > 0:
        print_error(f"Failed to patch: {total_failed} file(s)")
        sys.exit(1)
    else:
        print_success("All operations completed successfully!")
        sys.exit(0)

if __name__ == "__main__":
    main()
