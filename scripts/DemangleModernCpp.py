### Thin wrapper around llvm-cxxfilt that interfaces with the i64 db,
### unmangling symbols using modern C++ features which fail to get unmangled by IDA's old parser
### (e.g. modules)
###
###

import subprocess
import idautils
import ida_name
import ida_funcs
import shutil

def get_cxxfilt_cmd():
    if shutil.which("llvm-cxxfilt"):
        return ["llvm-cxxfilt"]
    # Hopefully safely falls back to this for windows platforms
    return [r"C:\Program Files\LLVM\bin\llvm-cxxfilt.exe"]

def demangle_with_llvm():
    cmd = get_cxxfilt_cmd()
    
    mangled_funcs = {}
    for addr in idautils.Functions():
        name = ida_funcs.get_func_name(addr)
        if name and name.startswith("_Z"):
            mangled_funcs[addr] = name

    if not mangled_funcs:
        return

    input_data = "\n".join(mangled_funcs.values())

    try:
        process_result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            check=True
        )
    except FileNotFoundError:
        print("Error: llvm-cxxfilt executable not found.")
        return
    except subprocess.SubprocessError as e:
        print(f"Subprocess error: {e}")
        return

    demangled_names = process_result.stdout.strip().split('\n')

    for addr, demangled_full in zip(mangled_funcs.keys(), demangled_names):
        if demangled_full:
            demangled_short = demangled_full.split('(')[0]
            if demangled_short and demangled_short != mangled_funcs[addr]:
                ida_name.set_name(addr, demangled_short, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
                print(f"Demangled: {mangled_funcs[addr]} -> {demangled_short}")

if __name__ == "__main__":
    demangle_with_llvm()
