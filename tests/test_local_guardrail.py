"""The local fast path must not allow commands that can launch other programs."""
import json
import unittest
from unittest.mock import patch

import httpx

from masqai.model import Session
from masqai.sanitize import Sanitizer, clearly_local_command
from tests.helpers import make_config


class LocalCommands(unittest.TestCase):
    def test_local_chains_and_paths(self):
        for command in ["cd <PATH_1234abcd>/sync && ls", "echo func <PATH_1234abcd>",
                        "cat <PATH_1234abcd> | grep needle; wc -l <PATH_1234abcd>",
                        "sqlite3 <PATH_1234abcd> 'select count(*) from t'",
                        "sqlite3 data.db 'select count(*) from t'"]:
            with self.subTest(command):
                self.assertTrue(clearly_local_command("bash", json.dumps({"command": command})))

    def test_execution_and_unknown_syntax_require_inspection(self):
        for command in ["python3 -c 'import sqlite3'", "git fetch", "echo x && scp k remote:/tmp",
                        "echo x | openssl s_client", "echo $(curl remote)", "echo `curl remote`",
                        "cat /dev/tcp/host/80", "find . -exec curl remote ;",
                        "sqlite3 data.db '.shell curl remote'", "sqlite3 -cmd '.load evil' data.db",
                        "sqlite3 data.db \"select load_extension('evil')\"",
                        "echo x & curl remote", "echo x\ncurl remote", "echo x > >(curl remote)"]:
            with self.subTest(command):
                self.assertFalse(clearly_local_command("bash", {"command": command}))

    def test_unknown_tool_requires_inspection(self):
        self.assertFalse(clearly_local_command("http_request", {"command": "echo value"}))


class InspectionPolicy(unittest.IsolatedAsyncioTestCase):
    async def test_python_local_database_is_inspected_and_can_be_allowed(self):
        calls = []

        def inspect(request):
            calls.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"decision":"allow"}'}}]})

        client_class = httpx.AsyncClient
        factory = lambda **kwargs: client_class(transport=httpx.MockTransport(inspect), **kwargs)
        ph = "<PATH_1234abcd>"
        with patch("httpx.AsyncClient", factory):
            allowed, _ = await Sanitizer(make_config(security=True)).inspect_inbound_tool_call(
                Session("local"), "bash", {"command": f"python3 -c \"import sqlite3; sqlite3.connect('{ph}')\""}, {ph}, {})
        self.assertTrue(allowed)
        self.assertEqual(len(calls), 1)
        prompt = json.loads(calls[0]["messages"][-1]["content"])["instruction"]
        self.assertIn("Reading and writing local files and local databases is allowed", prompt)
