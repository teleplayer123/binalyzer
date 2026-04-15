import os
import json
import signal
import subprocess
import sys
import sqlite3
import r2pipe
from openai import OpenAI

from tools.fuzzer import run_afl_fuzz, run_generate_fuzz_seed


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
DB_PATH = os.path.join(BASE_DIR, "agent_memory.db")

if not os.path.exists(TARGET_DIR):
    os.mkdir(TARGET_DIR)

if not os.path.exists(SEED_DIR):
    os.mkdir(SEED_DIR)

if not os.path.exists(OUTPUT_DIR):
    os.mkdir(OUTPUT_DIR)


client = OpenAI(base_url=LLM_API_URL, api_key="sk-no-key-required")

class SQLiteMemory:
    """Permanent storage for security findings."""
    def __init__(self, db_path):
        self.db_path = db_path
        self._setup_db()

    def _setup_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS triplets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_name TEXT,
                    subject TEXT,
                    relation TEXT,
                    object TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def add_finding(self, bin_name, s, r, o):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO triplets (binary_name, subject, relation, object) VALUES (?, ?, ?, ?)",
                (bin_name, s, r, o)
            )
        return f"Database Updated: {s} -> {r} -> {o}"

    def query(self, bin_name, node):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT subject, relation, object FROM triplets WHERE binary_name = ? AND (subject = ? OR object = ?)",
                (bin_name, node, node)
            )
            rows = cursor.fetchall()
        if not rows: return f"No historical knowledge found for '{node}'."
        return f"Historical Knowledge for {node}:\n" + "\n".join([f"{r[0]} {r[1]} {r[2]}" for r in rows])

class SecurityAgent:
    def __init__(self):
        self.db = SQLiteMemory(DB_PATH)
        self.history = [
            {"role": "system", "content": (
                "You are an expert Linux Security Researcher. "
                "1. Use 'perform_security_audit' first to map the binary. "
                "2. Use 'run_trace' with ltrace/strace to watch real-time execution. "
                "3. ALWAYS save critical findings to the DB via 'update_kg'. "
                "4. Access history with 'query_kg'. Be concise and technical."
            )},
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
        try:
            response = client.chat.completions.create(
                model="Qwen3",
                messages=[{"role": "user", "content": f"Summarize this technical data, highlighting risks/addresses:\n{raw_text[:5000]}"}]
            )
            return f"[SUMMARY]: {response.choices[0].message.content}"
        except:
            return f"[TRUNCATED DATA]: {raw_text[:1000]}"

    def prune_history(self):
        """Keep the conversation history within a manageable size."""
        if len(self.history) > MAX_HISTORY_MESSAGES:
            # Preserve the system prompt (index 0) and the last N messages
            print("[!] Pruning history to save context tokens.")
            self.history = [self.history[0]] + self.history[-(MAX_HISTORY_MESSAGES-1):]

    def run_trace(self, filename, tool="ltrace", args=""):
        """Hardware-lite dynamic analysis using ltrace or strace."""
        path = os.path.join(TARGET_DIR, os.path.basename(filename))
        # Ensure the binary is executable inside the container
        os.chmod(path, 0o755)
        
        # Capture stderr because that's where traces usually print
        cmd = f"timeout 10s {tool} {path} {args}"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            output = res.stderr if res.stderr else res.stdout
            return output if output else "[No trace output generated]"
        except Exception as e: return f"Trace Error: {e}"

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
        elif name == "run_trace":
            result = self.run_trace(args.get("filename"), args.get("tool", "ltrace"), args.get("args", ""))
        elif name == "update_kg":
            result = self.db.add_finding(args.get("binary"), args.get("s"), args.get("r"), args.get("o"))
        elif name == "query_kg":
            result = self.db.query(args.get("binary"), args.get("node"))
        else: 
            result = "Unknown tool."
        # Smart Memory Logic: Volatility and Summarization
        self.last_raw_output = result # Store in volatile memory for exactly one turn
        
        if len(result) > MAX_TOOL_CHARS:
            return self.summarize_content(result)
        return result
    
    def generate_fuzz_seed(self, filename, content_hex):
        """Creates a binary seed for AFL++ based on LLM suggestions."""
        os.makedirs(SEED_DIR, exist_ok=True)
        path = os.path.join(SEED_DIR, os.path.basename(filename))
        return run_generate_fuzz_seed(path, content_hex)
        
    def start_afl_fuzz(self, binary_name, timeout="60s"):
        """Starts AFL++ in QEMU mode."""
        target = os.path.join(TARGET_DIR, binary_name)
        # Ensure output dir exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        # -i: input seeds, -o: output crashes, -Q: QEMU mode for binaries without source
        cmd = f"timeout {timeout} afl-fuzz -i {SEED_DIR} -o {OUTPUT_DIR} -Q -- {target}"
        return run_afl_fuzz(cmd, OUTPUT_DIR)

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
            risky = ["system", "exec", "socket", "connect", "ptrace", "strcpy", "gets"]
            audit["flagged_apis"] = [i for i in audit["imports"] if any(s in i for s in risky)]
            return json.dumps(audit)
        except Exception as e: 
            return f"Audit Error: {e}"

    def chat(self, user_input):
        # Handle a special keyword to access volatile memory
        if "show raw" in user_input.lower() and self.last_raw_output:
            user_input += f"\n\n[RAW CONTEXT]: {self.last_raw_output}"

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
                        "properties": {
                            "filename": {"type": "string"}
                        },
                        "required": ["filename"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_trace",
                    "description": "Run binary with strace or ltrace to observe behavior.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filename": {"type": "string"},
                            "tool": {"type": "string", "enum": ["ltrace", "strace"]},
                            "args": {"type": "string"}
                        },
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
            },
            {
                "type": "function",
                "function": {
                    "name": "start_afl_fuzz",
                    "description": "Run AFL++ fuzzer on the target.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "binary_path": {"type": "string", "description": "Path to the target executable"},
                            "timeout": {"type": "string", "description": "Time to run in seconds (e.g., '60s')"}
                        },
                        "required": ["binary_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "update_kg",
                    "description": "Save finding to persistent SQLite DB.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "binary": {"type": "string"},
                            "s": {"type": "string", "description": "Subject"},
                            "r": {"type": "string", "description": "Relation"},
                            "o": {"type": "string", "description": "Object"}
                        },
                        "required": ["binary", "s", "r", "o"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "query_kg",
                    "description": "Recall data from persistent SQLite DB.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "binary": {"type": "string"},
                            "node": {"type": "string"}
                        },
                        "required": ["binary", "node"]
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
