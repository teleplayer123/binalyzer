import subprocess
import os
import binascii

#if issues with afl++ starting, run the following:
# echo core | sudo tee /proc/sys/kernel/core_pattern

# start_fuzzing_tool = {
#     "type": "function",
#     "function": {
#         "name": "start_afl_fuzz",
#         "description": "Starts an AFL++ fuzzing session on a target binary.",
#         "parameters": {
#             "type": "object",
#             "properties": {
#                 "binary_path": {"type": "string", "description": "Path to the target executable"},
#                 "timeout": {"type": "string", "description": "Time to run in seconds (e.g., '60s')"}
#             },
#             "required": ["binary_path"]
#         }
#     }
# }

def run_afl_fuzz(cmd, outdir):
    """Runs the AFL++ fuzzer with the given command and output directory."""
    try:
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return f"Fuzzing session finished. Check {outdir} for results."
    except Exception as e:
        return f"Fuzzing failed: {str(e)}"

# The tool definition for the LLM
# fuzz_seed_tool = {
#     "type": "function",
#     "function": {
#         "name": "generate_fuzz_seed",
#         "description": "Creates a binary seed file for fuzzing based on a hex string.",
#         "parameters": {
#             "type": "object",
#             "properties": {
#                 "filename": {"type": "string", "description": "Name of the seed file (e.g., 'seed_1.bin')"},
#                 "content_hex": {"type": "string", "description": "The hex representation of the binary data (e.g., '41414141')"}
#             },
#             "required": ["filename", "content_hex"]
#         }
#     }
# }

# The actual Python implementation
def run_generate_fuzz_seed(path, content_hex):
    try:
        binary_data = binascii.unhexlify(content_hex)
        with open(path, "wb") as f:
            f.write(binary_data)
        return f"Successfully created seed at {path}"
    except Exception as e:
        return f"Error: {str(e)}"