import unittest

from agent import SecurityContextManager

class SCMTestCase(unittest.TestCase):
    def setUp(self):
        self.ctx = SecurityContextManager(100)

    def test_add_ctx(self):
        role = "assistant"