from collections import deque
import difflib
import os
import json
import signal
import subprocess
import sys
import sqlite3
import r2pipe
import tiktoken
from openai import OpenAI

from lib.chat_logger import ChatLogger
from tools.pattern_generator import generate_pattern


# --- CONFIGURATION ---
#LLM_API_URL = "http://localhost:8001/v1"
LLM_API_URL = "http://host.containers.internal:8001/v1"
MAX_TOOL_CHARS = 2000  # Summarize if output exceeds this
MAX_HISTORY_MESSAGES = 15 # Keep the most recent turns
MAX_CONTEXT_TOKENS = 12000  # Safe ceiling
R2_TIMEOUT = 15
BASE_DIR = "/home/analyst"
TARGET_DIR = os.path.join(BASE_DIR, "target")
SEED_DIR = os.path.join(BASE_DIR, "fuzz_in")
SEED_FILE = os.path.join(SEED_DIR, "seed.txt")
OUTPUT_DIR = os.path.join(BASE_DIR, "fuzz_out")
DB_DIR = os.path.join(BASE_DIR, "db")
DB_PATH = os.path.join(DB_DIR, "agent_memory.db")

if not os.path.exists(TARGET_DIR):
    os.mkdir(TARGET_DIR)

if not os.path.exists(DB_DIR):
    os.mkdir(DB_DIR)

client = OpenAI(base_url=LLM_API_URL, api_key="sk-no-key-required")
logger = ChatLogger()

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
    
class SecurityContextManager:
    def __init__(self, max_tokens):
        self.encoder = tiktoken.get_encoding("cl100k_base")
        self.max_tokens = max_tokens
        self.history = deque()
        self.system_prompt = [
            {"role": "system", "content": (
                "You are an expert Linux Security Researcher. "
                "1. Use 'perform_security_audit' first to map the binary. "
                "2. Use 'run_trace' with ltrace/strace to watch real-time execution. "
                "3. ALWAYS save critical findings to the DB via 'update_kg'. "
                "4. Access history with 'query_kg'. Be concise and technical."
            )},
            {"role": "user", "content": "Wait for further instructions."}
        ]

    def _count(self, content):
        if not content: return 0
        return len(self.encoder.encode(str(content))) + 4

    def add(self, role, content=None, tool_calls=None, tool_call_id=None, name=None):
        msg = {"role": role}
        if content is not None: msg["content"] = content
        if tool_calls: msg["tool_calls"] = tool_calls
        if tool_call_id: 
            msg["tool_call_id"] = tool_call_id
            msg["name"] = name
            
        tokens = self._count(msg)
        self.history.append({"msg": msg, "tokens": tokens})
        self._prune()

    def _prune(self):
        total = sum(m["tokens"] for m in self.history) + self._count(self.system_prompt)
        # Keep system prompt + the last 3 messages always
        while total > self.max_tokens and len(self.history) > 3:
            removed = self.history.popleft()
            total -= removed["tokens"]

    def get_messages(self):
        return self.system_prompt + [m["msg"] for m in self.history]


class SecurityAgent:
    def __init__(self):
        self.db = SQLiteMemory(DB_PATH)
        self.ctx = SecurityContextManager(MAX_CONTEXT_TOKENS)

        response = client.chat.completions.create(
            model="Qwen3",
            messages=self.ctx.system_prompt,
            tools=self.get_tool_schemas(),
            tool_choice="auto"
        )
        print(response, file=sys.stderr)

    def summarize_content(self, raw_text):
        """Internal call to the LLM to condense massive tool output."""
        print("[*] Summarizing data...", file=sys.stderr)
        try:
            response = client.chat.completions.create(
                model="Qwen3",
                messages=[{"role": "user", "content": f"Summarize this technical data, highlighting risks/addresses:\n{raw_text[:5000]}"}]
            )
            return f"[SUMMARY]: {response.choices[0].message.content}"
        except:
            print("[!] Output too large. Truncating...", file=sys.stderr)
            return f"[TRUNCATED DATA]: {raw_text[:1000]}"

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
        except Exception as e: 
            return f"Trace Error: {e}"

    def execute_tool(self, name, args):
        """Executes tools and handles the 'Smart Memory' logic."""
        result = ""
        # Routing tool calls
        if name == "run_radare2_cmd":
            result = self.run_r2(args.get("filename"), args.get("command"))
        elif name == "perform_security_audit":
            result = self.run_audit(args.get("filename"))
        elif name == "generate_fuzz_seed":
            result = self.generate_fuzz_seed(args.get("length"), args.get("filename", SEED_FILE))
        elif name == "start_afl_fuzz":
            result = self.start_afl_fuzz(args.get("filename"), args.get("timeout", "60s"))
        elif name == "run_trace":
            result = self.run_trace(args.get("filename"), args.get("tool", "ltrace"), args.get("args", ""))
        elif name == "update_kg":
            result = self.db.add_finding(args.get("binary"), args.get("s"), args.get("r"), args.get("o"))
        elif name == "query_kg":
            result = self.db.query(args.get("binary"), args.get("node"))
        else: 
            result = "Unknown tool."
        
        if len(result) > MAX_TOOL_CHARS:
            return self.summarize_content(result)
        return result

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
            r2 = r2pipe.open(path, flags=["-e bin.cache=true"])
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
            self._r2_exec(path, "aaa")
            audit = {
                "entry_point": self._r2_exec(path, "iej"),
                "address_information": self._r2_exec(path, "aflj"),
                "mitigations": self._r2_exec(path, "iIj"),
                "imports": self._r2_exec(path, "iij"),
                "entropy": self._r2_exec(path, "iSj"),
                "strings": [s["string"] for s in self._r2_exec(path, "izj") if len(s["string"]) > 7][:20]
            }
            risky = ["system", "exec", "socket", "connect", "ptrace", "strcpy", "gets"]
            audit["flagged_apis"] = [i for i in audit["imports"] if any(s in i for s in risky)]
            return json.dumps(audit)
        except Exception as e: 
            return f"Audit Error: {e}"
        
    def generate_fuzz_seed(self, length, filename):
        """Creates a binary seed for AFL++"""
        os.makedirs(SEED_DIR, exist_ok=True)
        path = os.path.join(SEED_DIR, os.path.basename(filename))
        content = generate_pattern(length)
        try:
            with open(path, "w") as f:
                f.write(content)
            return f"Seed created at {path}"
        except Exception as e:
            return f"Seed Error: {str(e)}"
        
    def start_afl_fuzz(self, filename, timeout="60s"):
        """Starts AFL++ in QEMU mode."""
        target = os.path.join(TARGET_DIR, filename)
        # Ensure output dir exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        cmd = f"timeout {timeout} afl-fuzz -i {SEED_DIR} -o {OUTPUT_DIR} -Q -- {target}"
        try:
            subprocess.run(cmd, shell=True, capture_output=True)
            return f"Fuzzing complete. Results in {OUTPUT_DIR}"
        except Exception as e:
            return f"Fuzzing failed: {str(e)}"

    def chat(self, user_input):
        self.ctx.add("user", user_input)
        logger.log_message("user", user_input)
        
        while True:
            response = client.chat.completions.create(
                model="Qwen3",
                messages=self.ctx.get_messages(),
                tools=self.get_tool_schemas(),
                tool_choice="auto"
            )
            logger.log_info(f"Response: {response}")

            msg = response.choices[0].message
            logger.log_info(f"Message: {msg}")

            self.ctx.add("assistant", content=msg.content, tool_calls=msg.tool_calls)
            logger.log_message(msg.role, f"Content: {msg.content}, ToolCall: {msg.tool_calls}")

            if not msg.tool_calls:
                logger.log_message(msg.role, msg.content)
                print(f"[*] Returning from Chat -> Role: {msg.role} Content: {msg.content}", file=sys.stderr)
                return msg.content
            
            for tool_call in msg.tool_calls:
                logger.log_info(f"Tool Call: {tool_call}")
                print(f"[*] Tool Call: {tool_call.function.name}", file=sys.stderr)
                print(f"[*] Executing Args: {tool_call.function.arguments}", file=sys.stderr)
                result = self.execute_tool(tool_call.function.name, json.loads(tool_call.function.arguments))
                logger.log_tool_output(tool_call.function.name, tool_call.function.arguments, result)
                self.ctx.add("tool", content=result, tool_call_id=tool_call.id, name=tool_call.function.name)

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
                    "description": "Creates a random fuzzing pattern string from specified length and writes to a file.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                           "length": {"type": "integer", "description": "Length of the fuzzing pattern to generate."},
                           "filename": {"type": "string", "description": "Name of the file that the generated pattern is written to."}
                        },
                        "required": ["length"]
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
                        "properties": {"filename": {"type": "string"}, "timeout": {"type": "string"}},
                        "required": ["filename"]
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
        if len(query) == 0:
            continue
        if query.lower() in ['exit', 'quit']: 
            break
        res = agent.chat(query)
        if len(res) > 0:
            print(f"\n[Agent]: {res}", file=sys.stderr)