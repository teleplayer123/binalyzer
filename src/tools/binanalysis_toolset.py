import lief
from capstone import *
import subprocess
import json

def analyze_binary_headers(filepath):
    """Extracts basic info, imports, and exports from a binary."""
    binary = lief.parse(filepath)
    if not binary:
        return "Could not parse file."
    
    info = {
        "format": str(binary.format),
        "entrypoint": hex(binary.entrypoint),
        "imported_functions": [imp.name for imp in binary.imports],
        "exported_functions": [exp.name for exp in binary.exports]
    }
    return json.dumps(info, indent=2)

def disassemble_at_address(filepath, address, count=20):
    """Disassembles code at a specific memory address."""
    binary = lief.parse(filepath)
    # Simplified: finding the raw bytes at a virtual address
    # In a real tool, you'd use a library like r2pipe for better mapping
    raw_code = binary.get_content_from_virtual_address(address, count * 4) 
    
    md = Cs(CS_ARCH_X86, CS_MODE_64) # Adjust based on binary arch
    assembly = []
    for i in md.disasm(bytes(raw_code), address):
        assembly.append(f"{hex(i.address)}: {i.mnemonic} {i.op_str}")
    
    return "\n".join(assembly)

def triage_crash(binary_path, crash_input_path):
    """Executes the binary with a crashing input inside GDB to get a backtrace."""
    # Command to run gdb, hit the crash, print backtrace, and quit
    gdb_cmd = [
        "gdb", "-batch",
        "-ex", f"run < {crash_input_path}",
        "-ex", "bt",
        "--args", binary_path
    ]
    
    try:
        result = subprocess.run(gdb_cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Triage failed: {str(e)}"

