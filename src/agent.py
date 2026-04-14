import binascii
import os
import json
import signal
import subprocess
import sys
import r2pipe
from openai import OpenAI

# --- CONFIGURATION ---
#LLM_API_URL = "http://localhost:8001/v1"
LLM_API_URL = "http://host.containers.internal:8001/v1"
MAX_TOOL_CHARS = 2000  # Summarize if output exceeds this
MAX_HISTORY_MESSAGES = 15 # Keep the most recent turns
R2_TIMEOUT = 15
BASE_DIR = "/home/analyst"
TARGET_DIR = os.path.join(BASE_DIR, "target")
SEED_DIR = os.path.join(BASE_DIR, "fuzz_in")
OUTPUT_DIR = os.path.join(BASE_DIR, "fuzz_out")

client = OpenAI(base_url=LLM_API_URL, api_key="sk-no-key-required")

class SecurityAgent:
    def __init__(self):
        self.history = [
            {"role": "system", "content": "You are a Linux Security Expert. Efficiently audit binaries. If tool output is a [SUMMARY], trust the previous analysis."},
            {"role": "user", "content": "Wait for further instructions."}
        ]
        response = client.chat.completions.create(
            model="Qwen3",
            messages=self.history,
            tools=self.get_tool_schemas(),
            tool_choice="auto"
        )
        print(response, file=sys.stderr)
        # Volatile storage for raw data that shouldn't clog long-term memory
        self.last_raw_output = None 

    def summarize_content(self, raw_text):
        """Internal call to the LLM to condense massive tool output."""
        print("[!] Tool output too large. Summarizing...", file=sys.stderr)
        prompt = f"Summarize the following technical output. Keep all memory addresses, function names, and suspicious indicators: \n\n{raw_text[:8000]}"
        
        try:
            response = client.chat.completions.create(
                model="Qwen3",
                messages=[{"role": "user", "content": prompt}]
            )
            return f"[SUMMARY]: {response.choices[0].message.content}"
        except:
            return f"[TRUNCATED DATA]: {raw_text[:1000]}... [Data too large to process]"

    def prune_history(self):
        """Keep the conversation history within a manageable size."""
        if len(self.history) > MAX_HISTORY_MESSAGES:
            # Preserve the system prompt (index 0) and the last N messages
            print("[!] Pruning history to save context tokens.")
            self.history = [self.history[0]] + self.history[-(MAX_HISTORY_MESSAGES-1):]

    def execute_tool(self, name, args):
        """Executes tools and handles the 'Smart Memory' logic."""
        result = ""
        # Routing tool calls
        if name == "run_radare2_cmd":
            result = self.run_r2(args.get("filename"), args.get("command"))
        elif name == "perform_security_audit":
            result = self.run_audit(args.get("filename"))
        elif name == "generate_fuzz_seed":
            result = self.generate_fuzz_seed(args.get("filename"), args.get("content_hex"))
        elif name == "start_afl_fuzz":
            result = self.start_afl_fuzz(args.get("binary_name"), args.get("timeout", "30s"))

        # Smart Memory Logic: Volatility and Summarization
        self.last_raw_output = result # Store in volatile memory for exactly one turn
        
        if len(result) > MAX_TOOL_CHARS:
            return self.summarize_content(result)
        return result
    
    def generate_fuzz_seed(self, filename, content_hex):
        """Creates a binary seed for AFL++ based on LLM suggestions."""
        os.makedirs(SEED_DIR, exist_ok=True)
        path = os.path.join(SEED_DIR, os.path.basename(filename))
        try:
            with open(path, "wb") as f:
                f.write(binascii.unhexlify(content_hex))
            return f"Seed created at {path}"
        except Exception as e:
            return f"Seed Error: {str(e)}"
        
    def start_afl_fuzz(self, binary_name, timeout="60s"):
        """Starts AFL++ in QEMU mode."""
        target = os.path.join(TARGET_DIR, binary_name)
        # Ensure output dir exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        cmd = f"timeout {timeout} afl-fuzz -i {SEED_DIR} -o {OUTPUT_DIR} -Q -- {target}"
        try:
            subprocess.run(cmd, shell=True, capture_output=True)
            return f"Fuzzing complete. Results in {OUTPUT_DIR}"
        except Exception as e:
            return f"Fuzzing failed: {str(e)}"

    def _timeout_handler(self, signum, frame):
        raise TimeoutError("Command timed out.")
    
    def run_r2(self, filename, command):
        """Direct r2 access for the LLM to explore specific addresses."""
        path = os.path.join(TARGET_DIR, os.path.basename(filename))
        try:
            r2 = r2pipe.open(path)
            r2.cmd("aa")
            res = r2.cmd(command)
            r2.quit()
            return res
        except Exception as e:
            return f"r2 Error: {str(e)}"

    def _r2_exec(self, path, command):
        cmd = command.replace("\n", " ").strip()
        signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.alarm(R2_TIMEOUT)
        try:
            r2 = r2pipe.open(path)
            output = r2.cmd(cmd)
            r2.quit()
            signal.alarm(0)
            return json.loads(output.strip("\n")) if output else "[No output]"
        except Exception as e:
            signal.alarm(0)
            return f"R2 Error: {str(e)}"

    def run_audit(self, filename):
        """Bundled tool for rapid security assessment."""
        path = os.path.join(TARGET_DIR, os.path.basename(filename))
        try:
            audit = {
                "entry_point": self._r2_exec(path, "iej"),
                "address_information": self._r2_exec(path, "aflj"),
                "mitigations": self._r2_exec(path, "iIj"),
                "imports": self._r2_exec(path, "iij"),
                "entropy": self._r2_exec(path, "iSj"),
                "strings": [s["string"] for s in self._r2_exec(path, "izzj") if len(s["string"]) > 15][:20]
            }
            risky = ["system", "exec", "socket", "connect", "ptrace"]
            audit["flagged_apis"] = [i for i in audit["imports"] if any(s in i for s in risky)]
            return json.dumps(audit)
        except Exception as e: 
            return f"Audit Error: {e}"

    def chat(self, user_input):
        # Handle a special keyword to access volatile memory
        if "show raw" in user_input.lower() and self.last_raw_output:
            user_input += f"\n\nContext from previous tool: {self.last_raw_output}"

        self.history.append({"role": "user", "content": user_input})
        
        while True:
            response = client.chat.completions.create(
                model="Qwen3",
                messages=self.history,
                tools=self.get_tool_schemas(),
                tool_choice="auto"
            )

            msg = response.choices[0].message
            self.history.append(msg)

            if not msg.tool_calls:
                self.prune_history() # Clean up before next turn
                return msg.content

            for tool_call in msg.tool_calls:
                print(f"[*] Tool Call: {tool_call.function.name}", file=sys.stderr)
                print(f"[*] Executing Args: {tool_call.function.arguments}", file=sys.stderr)
                result = self.execute_tool(tool_call.function.name, json.loads(tool_call.function.arguments))
                
                self.history.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": tool_call.function.name,
                    "content": result
                })

    def get_tool_schemas(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": "perform_security_audit",
                    "description": "Analyze binary protections, strings, and suspicious API imports.",
                    "parameters": {
                        "type": "object",
                        "properties": {"filename": {"type": "string"}},
                        "required": ["filename"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_radare2_cmd",
                    "description": "Run custom radare2 commands (e.g., 'pdf @ main', 'aflj').",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filename": {"type": "string"},
                            "command": {"type": "string"}
                        },
                        "required": ["filename", "command"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "generate_fuzz_seed",
                    "description": "Create a binary seed file from hex for fuzzing.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filename": {"type": "string"},
                            "content_hex": {"type": "string"}
                        },
                        "required": ["filename", "content_hex"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "start_afl_fuzz",
                    "description": "Run AFL++ fuzzer on the target.",
                    "parameters": {
                        "type": "object",
                        "properties": {"binary_name": {"type": "string"}, "timeout": {"type": "string"}},
                        "required": ["binary_name"]
                    }
                }
            }
        ]

# --- MAIN LOOP ---
if __name__ == "__main__":
    agent = SecurityAgent()
    print("--- Security Agent ---", file=sys.stderr)
    while True:
        query = input("\n[User]: ")
        if query.lower() in ['exit', 'quit']: break
        print(f"\n[Agent]: {agent.chat(query)}", file=sys.stderr)
