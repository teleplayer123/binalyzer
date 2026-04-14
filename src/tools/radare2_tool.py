import r2pipe
import json
import os

analyze_with_r2_tool = {
    "type": "function",
    "function": {
        "name": "run_radare2_cmd",
        "description": "Run a radare2 command on a binary to get deep analysis metadata.",
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "The binary to analyze"},
                "command": {
                    "type": "string", 
                    "description": "The r2 command to run (e.g., 'iIj' for info, 'aflj' for functions, 'pdfj @ main' for disassembly)."
                }
            },
            "required": ["filename", "command"]
        }
    }
}

def run_radare2_cmd(filename, command):
    # Security: Ensure we are only looking in the analyst directory
    safe_path = f"/home/analyst/target_binaries/{os.path.basename(filename)}"
    
    try:
        r2 = r2pipe.open(safe_path)
        # Perform basic analysis (aa) before running commands if needed
        r2.cmd("aa") 
        
        # Execute command and return JSON/text
        output = r2.cmd(command)
        r2.quit()
        return output
    except Exception as e:
        return f"Radare2 error: {str(e)}"

def perform_security_audit(filename):
    """
    Runs a comprehensive security check on a Linux ELF.
    Returns: JSON string containing protections, suspicious imports, and entropy.
    """
    # Ensure path is safe/local to your Docker workspace
    safe_path = f"/home/analyst/target_binaries/{os.path.basename(filename)}"
    
    try:
        r2 = r2pipe.open(safe_path)
        r2.cmd("aa") # Analyze all
        
        audit = {
            # 1. Binary Protections (NX, Canary, ASLR/Relro)
            "mitigations": json.loads(r2.cmd("iIj")),
            
            # 2. Suspicious Imports (Network, Shell, Process manipulation)
            "imports": [imp["name"] for imp in json.loads(r2.cmd("iij"))],
            
            # 3. High-entropy sections (Detects packed malware)
            "sections": json.loads(r2.cmd("iSj")),
            
            # 4. Critical strings (IPs, file paths, shell commands)
            "strings": [s["string"] for s in json.loads(r2.cmd("izzj")) if len(s["string"]) > 8]
        }
        
        # Filter for 'scary' imports
        scary_list = ["system", "execve", "fork", "socket", "connect", "ptrace", "mmap"]
        audit["risk_imports"] = [i for i in audit["imports"] if any(s in i for s in scary_list)]
        
        r2.quit()
        return json.dumps(audit, indent=2)
    except Exception as e:
        return f"Audit failed: {str(e)}"

