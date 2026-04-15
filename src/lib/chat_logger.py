import logging
import os

BASE_DIR = "/home/analyst"

class ChatLogger:
    def __init__(self, log_file="chat_history.log"):
        logging.basicConfig(filename=os.path.join(BASE_DIR, log_file), level=logging.INFO, format='%(asctime)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def log_message(self, role, content):
        self.logger.info(f"{role.upper()}: {content}")
    
    def log_tool_output(self, tool_name, args, output):
        self.logger.info(f"TOOL OUTPUT - {tool_name}({args}): {output}")
    
    def log_summary(self, summary):
        self.logger.info(f"SUMMARY: {summary}")