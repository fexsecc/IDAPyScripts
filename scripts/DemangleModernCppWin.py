import subprocess
import glob
import idautils
import ida_name
import ida_funcs
import shutil
import re
import os

def get_undname_cmd():
    if shutil.which("undname"):
        return ["undname"]

    vswhere_path = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)") + r"\Microsoft Visual Studio\Installer\vswhere.exe"
    if not os.path.exists(vswhere_path):
        return None

    try:
        result = subprocess.run(
            [
                vswhere_path,
                "-latest",
                "-products", "*",
                "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property", "installationPath"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        install_path = result.stdout.strip().split('\n')[0]
        if not install_path:
            return None

        search_pattern = os.path.join(
            install_path, 
            "VC", "Tools", "MSVC", "*", "bin", "Hostx64", "x64", "undname.exe"
        )
        
        matches = glob.glob(search_pattern)
        if matches:
            print(f"[+] Found undname at {matches[0]}")
            return [matches[0]]
            
    except subprocess.SubprocessError:
        pass

    return None

def preprocess_symbol(mangled_name):
    core_name = mangled_name
    prefix = ""
    suffix = ""
    
    if core_name.startswith("j_?"):
        prefix = "j_"
        core_name = core_name[2:]
        
    suffix_match = re.search(r'(__+[A-Za-z0-9_]+)$', core_name)
    if suffix_match:
        suffix = suffix_match.group(1)
        core_name = core_name[:-len(suffix)]
        
    return prefix, core_name, suffix

def demangle_with_msvc():
    cmd_base = get_undname_cmd()
    
    if not cmd_base:
        print("Error: Could not locate undname.exe via PATH or vswhere.")
        return
        
    mangled_funcs = {}
    for addr in idautils.Functions():
        name = ida_funcs.get_func_name(addr)
        if name and ("?" in name):
            mangled_funcs[addr] = name

    if not mangled_funcs:
        return

    addrs = []
    original_names = []
    core_names_to_demangle = []
    wrappers = []
    
    for addr, name in mangled_funcs.items():
        prefix, core_name, suffix = preprocess_symbol(name)
        if not core_name.startswith("?"):
            continue
            
        addrs.append(addr)
        original_names.append(name)
        core_names_to_demangle.append(core_name)
        wrappers.append((prefix, suffix))

    if not core_names_to_demangle:
        return

    cmd_base_str = " ".join(cmd_base + ["0x1000"])
    current_cmd_len = len(cmd_base_str)
    
    chunks = []
    current_chunk_indices = []
    
    for i, core_name in enumerate(core_names_to_demangle):
        added_len = len(core_name) + 1
        
        # Max Windows cmdline length is ~32767. Keep a safe buffer by triggering at 32000.
        if current_cmd_len + added_len > 32000:
            chunks.append(current_chunk_indices)
            current_chunk_indices = [i]
            current_cmd_len = len(cmd_base_str) + added_len
        else:
            current_chunk_indices.append(i)
            current_cmd_len += added_len
            
    if current_chunk_indices:
        chunks.append(current_chunk_indices)

    for chunk_indices in chunks:
        chunk_core_names = [core_names_to_demangle[i] for i in chunk_indices]
        cmd = cmd_base + ["0x1000"] + chunk_core_names

        try:
            process_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
        except FileNotFoundError:
            print("Error: undname executable not found during execution.")
            return
        except subprocess.SubprocessError as e:
            print(f"Subprocess error: {e}")
            return

        matches = re.findall(r'is :-\s+"([^"]+)"', process_result.stdout)

        if len(matches) != len(chunk_core_names):
            print("Warning: Mismatch between input symbols and parsed output in this chunk.")
            continue

        for i, demangled_full in zip(chunk_indices, matches):
            addr = addrs[i]
            original = original_names[i]
            prefix, suffix = wrappers[i]
            core_name = core_names_to_demangle[i]
            
            if demangled_full and demangled_full != core_name:
                demangled_short = demangled_full.split('(')[0].strip()
                final_name = f"{prefix}{demangled_short}{suffix}"
                
                if final_name and final_name != original:
                    ida_name.set_name(addr, final_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
                    print(f"Demangled: {original} -> {final_name}")

if __name__ == "__main__":
    demangle_with_msvc()
