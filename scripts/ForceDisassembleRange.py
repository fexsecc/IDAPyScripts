# Force IDA to disassemble a range of memory offsets
# It seems if IDA does not see an xref to a certain function,
# It does not analyze it (Probably better for reversing anti-tamper which employs deadcode and etc.)
# It is useful to do this however when dealing with firmware,
# e.g for an 8051 ROM image.
#
# Usage: ForceDisassembleRange(0, 0x1fff)
import idc
import ida_bytes

def ForceDisassembleRange(StartAddress, EndAddress):
    CurrentEa = StartAddress

    while CurrentEa != idc.BADADDR and CurrentEa < EndAddress:
        Flags = ida_bytes.get_flags(CurrentEa)
        
        if ida_bytes.is_unknown(Flags):
            idc.create_insn(CurrentEa)
            
        CurrentEa += idc.get_item_size(CurrentEa)
        
    print(f"Forced disassembly completed from {hex(StartAddress)} to {hex(EndAddress)}.")
