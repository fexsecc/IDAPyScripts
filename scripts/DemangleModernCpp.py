### Thin wrapper around llvm-cxxfilt that interfaces with the i64 db,
### unmangling symbols using modern C++ features which fail to get unmangled by IDA's old parser
### (e.g. modules)
###
###

import subprocess
import idautils
import ida_name
import ida_funcs

def DemangleWithLlvm():
    for FunctionAddress in idautils.Functions():
        MangledName = ida_funcs.get_func_name(FunctionAddress)
        
        if MangledName and MangledName.startswith("_Z"):
            try:
                ProcessResult = subprocess.run(
                    ["llvm-cxxfilt", MangledName],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                DemangledName = ProcessResult.stdout.strip().split('(')[0]
                
                if DemangledName and DemangledName != MangledName:
                    ida_name.set_name(FunctionAddress, DemangledName, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
                    print(f"Demangled: {MangledName} -> {DemangledName}")
                    
            except subprocess.SubprocessError:
                pass

if __name__ == "__main__":
    DemangleWithLlvm()
