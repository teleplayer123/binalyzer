import base64 as b64
import ollama
import os
import sqlite3
import sys

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.create_tables()

    def create_tables(self):
        with sqlite3.connect(self.db_path) as db:
            cursor = db.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_input TEXT,
                    response TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def log_conversation(self, user_input, response):
        with sqlite3.connect(self.db_path) as db:
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO conversations (user_input, response)
                VALUES (?, ?)
            """, (user_input, response))

    def fetch_conversations(self):
        with sqlite3.connect(self.db_path) as db:
            cursor = db.cursor()
            res = cursor.execute("SELECT * FROM conversations")
            return res.fetchall()

class REAssistent:
    def __init__(self, db_filename="re_assist.db"):
        self.messages = [
            {
                "role": "assistant",
                "content": "Your profession is Reverse Engineer. You specialize in binary analysis and security. You answer all questions in detail. If you are unsure about a question, ask for clarification. If the user input is not clear, ask for more details.",
            },
        ]
        self.client = ollama.Client(host='http://localhost:11434')
        self.db_manager = DatabaseManager(db_filename)

    def get_response(self, user_input):
        self.messages.append({"role": "user", "content": user_input})
        response = self.client.chat(model="gemma3:1b", messages=self.messages)
        self.messages.append({"role": "assistant", "content": response["message"]["content"]})
        self.db_manager.log_conversation(user_input, response["message"]["content"])
        return response["message"]["content"]
    
    def _fetch_conversations(self):
        return self.db_manager.fetch_conversations()
    
    def _handle_file_argument(self, argument):
        if os.path.isfile(argument):
            if not os.access(argument, os.R_OK):
                return "Error: File is not readable."
            if argument.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.bin', '.exe', '.dll', '.so')):
                with open(argument, "rb") as fh:
                    content = fh.read()
                content = b64.b64encode(content).decode('utf-8')
                #content = f"data:application/octet-stream;base64,{content}"
            elif argument.endswith(('.txt', '.md', '.json', '.xml', '.yaml', '.yml', '.csv', '.log', '.ini', '.cfg', '.py', '.c', '.cpp', '.h', '.java', '.js', '.html', '.css')):
                with open(argument, "r") as fh:
                    content = fh.read()
            else:
                return "Error: Unsupported file type."
            return content
        else:
            return None
    
    def process_input(self, user_input):
        if len(user_input.split(":")) == 2:
            # User input format: "instruction: argument"
            instruction, argument = user_input.split(":")
            instruction = instruction.strip().lower()
            argument = argument.strip()
            # Handle arguments that are file paths
            if os.path.isfile(argument):
                content = self._handle_file_argument(argument)
                if content is None:
                    return "Error: File does not exist."
                else:
                    return self.get_response(f"{instruction}:\n{content}")
            else:
                return self.get_response(f"{instruction}: {argument}")
        else:
            if user_input.startswith("fetch_conversations"):
                conversations = self._fetch_conversations()
                formatted_conversations = "\n".join([f"ID: {conv[0]}, User Input: {conv[1]}, Response: {conv[2]}, Timestamp: {conv[3]}" for conv in conversations])
                return formatted_conversations if formatted_conversations else "No conversations found."
            elif user_input.lower() in ["exit", "quit"]:
                self.close()
                return "Session ended."
            elif user_input.lower() == "help":
                return """Available commands:
                            - fetch_conversations: Retrieve all past conversations.
                            - exit or quit: End the session.
                            - help: Show this help message.
                            Input can use the format "instruction: argument" where argument can be a file path, or text input without an argument.
                            Supported file types: .png, .jpg, .jpeg, .bmp, .gif, .bin, .exe, .dll, .so, .txt, .md, .json, .xml, .yaml, .yml, .csv, .log, .ini, .cfg, .py, .c, .cpp, .h, .java, .js, .html, .css
                        """
            else:
                return self.get_response(user_input)
    
    def close(self):
        sys.exit(0)


if __name__ == "__main__":
    ra = REAssistent()

    while True:
        user_input = input("> ")
        response = ra.process_input(user_input)
        print(f"\n{response}\n")