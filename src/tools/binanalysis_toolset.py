import lief
import capstone as cs
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
    raw_code = binary.get_content_from_virtual_address(address, count * 4) 
    
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64) # Adjust based on binary arch
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

class BinDisasm:

    def __init__(self, filename, arch="arm", mode="arm", size=None):
        self.filename = filename
        self._size = size
        self._data_fd = None
        self.data = None
        self._code = None
        self._dis = None

        self._archs = {
            "arm": cs.CS_ARCH_ARM,
            "arm64": cs.CS_ARCH_ARM64,
            "x86": cs.CS_ARCH_X86,
            "mips": cs.CS_ARCH_MIPS
        }
        self._modes = {
            "x86": cs.CS_MODE_32,
            "x86_64": cs.CS_MODE_64,
            "arm": cs.CS_MODE_ARM,
            "mips32": cs.CS_MODE_MIPS32,
            "mips64": cs.CS_MODE_MIPS64,
            "thumb": cs.CS_MODE_THUMB
        }
        try:
            self._arch = self._archs[arch]
            self._mode = self._modes[mode]
        except KeyError:
            raise KeyError("arch or mode are not supported.")

    def _get_code(self, offset=0):
        self._dis = cs.Cs(self._arch, self._mode)
        code = self._dis.disasm(self.data, offset=offset)
        return [ins for ins in code]
    
    def reconfig_mode(self, mode):
        if self._dis is not None:
            self._dis.mode = mode
        else:
            raise EnvironmentError("File must be parsed before reconfiguring mode.")
        
    def set_syntax(self, syntax):
        if self._dis is not None:
            self._dis.syntax = syntax
        else:
            raise EnvironmentError("File must be parsed before setting syntax format.")

    def parse_code(self, offset=0):
        ins_info = {}
        code = self._get_code(offset)
        for i in code:
            ins_by_addr = {
                "address": i.address,
                "mnemonic": i.mnemonic,
                "operation": i.op_str
            }
            ins_info[str(i.address)] = ins_by_addr
        return ins_info

    def __enter__(self):
        self._data_fd = open(self.filename, "rb")
        if self._size is not None and type(self._size) == int:
            self.data = self._data_fd.read(self._size)
        else:
            self.data = self._data_fd.read()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._data_fd.close()