import unittest

from agent import SecurityContextManager

class SCMTestCase(unittest.TestCase):
    def setUp(self):
        self.ctx = SecurityContextManager(100)

    def test_add_toolcall_results(self):
        """add(self, role, content=None, tool_calls=None, tool_call_id=None, name=None)"""
        role = "tool"
        content = "Database Updated: xz.bin -> ARCH -> ARM 64-bit (aarch64)"
        name = "update_kg"
        toolcall_id = "id"
        self.ctx.add(role, content=content, name=name, tool_call_id=toolcall_id)
        res = self.ctx.get_messages()
        self.assertIsNotNone(res)
        print(f"Context Added: {res}")
