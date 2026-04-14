import subprocess
import os
import binascii

#if issues with afl++ starting, run the following:
# echo core | sudo tee /proc/sys/kernel/core_pattern

start_fuzzing_tool = {
    "type": "function",
    "function": {
        "name": "start_afl_fuzz",
        "description": "Starts an AFL++ fuzzing session on a target binary.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the target executable"},
                "timeout": {"type": "string", "description": "Time to run in seconds (e.g., '60s')"}
            },
            "required": ["binary_path"]
        }
    }
}

def start_afl_fuzz(binary_path, timeout="30s"):
    """Runs AFL++ in QEMU mode (no need to recompile the target)."""
    # -i: input seeds, -o: output crashes, -Q: QEMU mode for binaries without source
    cmd = f"timeout {timeout} afl-fuzz -i /home/analyst/fuzz_in -o /home/analyst/fuzz_out -Q -- {binary_path}"
    
    try:
        # We run this in the background or with a timeout
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return f"Fuzzing session finished. Check /home/analyst/fuzz_out/crashes for results."
    except Exception as e:
        return f"Fuzzing failed: {str(e)}"

# The tool definition for the LLM
fuzz_seed_tool = {
    "type": "function",
    "function": {
        "name": "generate_fuzz_seed",
        "description": "Creates a binary seed file for fuzzing based on a hex string.",
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Name of the seed file (e.g., 'seed_1.bin')"},
                "content_hex": {"type": "string", "description": "The hex representation of the binary data (e.g., '41414141')"}
            },
            "required": ["filename", "content_hex"]
        }
    }
}

# The actual Python implementation
def generate_fuzz_seed(filename, content_hex):
    # Ensure we only write to the designated seeds directory
    base_dir = "/workspace/fuzz_seeds"
    os.makedirs(base_dir, exist_ok=True)
    
    filepath = os.path.join(base_dir, os.path.basename(filename))
    
    try:
        binary_data = binascii.unhexlify(content_hex)
        with open(filepath, "wb") as f:
            f.write(binary_data)
        return f"Successfully created seed at {filepath}"
    except Exception as e:
        return f"Error: {str(e)}"