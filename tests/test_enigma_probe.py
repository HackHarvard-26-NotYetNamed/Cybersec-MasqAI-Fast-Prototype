import argparse
import os
from unittest.mock import AsyncMock
import unittest
from unittest.mock import patch

from eval import enigma_probe
from tests.helpers import FAKE_MGMT_KEY, FAKE_WORKSPACE, FakeOpenRouter


class ProbeArguments(unittest.TestCase):
    def test_live_run_requires_budget_confirmation(self):
        args = argparse.Namespace(workspace=FAKE_WORKSPACE, samples=1, rate_minutes=0, rate_interval=10,
                                  execute=True, confirm_budget=False)
        with self.assertRaisesRegex(ValueError, "--confirm-budget"):
            enigma_probe._validate(args)

    def test_sample_and_rate_bounds_are_enforced(self):
        for changes in ({"samples": 21}, {"rate_minutes": 6}, {"rate_interval": 11}):
            args = argparse.Namespace(workspace=FAKE_WORKSPACE, samples=1, rate_minutes=0, rate_interval=10,
                                      execute=False, confirm_budget=False)
            for name, value in changes.items():
                setattr(args, name, value)
            with self.assertRaises(ValueError):
                enigma_probe._validate(args)

    def test_missing_injected_credential_fails_without_network(self):
        with patch.dict(os.environ, {enigma_probe.ENV_KEY: ""}, clear=False), \
             patch.object(enigma_probe, "ENV_FILE", "missing-ormanagement.env"), patch("builtins.print") as output:
            self.assertEqual(enigma_probe.main(["--workspace", FAKE_WORKSPACE]), 2)
            self.assertNotIn(FAKE_MGMT_KEY, str(output.call_args_list))

    def test_env_file_reads_expected_assignment_and_strips_quotes(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as directory:
            env_file = Path(directory) / "ormanagement.env"
            env_file.write_text('UNRELATED=x\nOPENROUTER_MANAGEMENT_KEY="synthetic-test-secret"\n', encoding="utf-8")
            with patch.dict(os.environ, {enigma_probe.ENV_KEY: ""}, clear=False):
                self.assertEqual(enigma_probe._load_management_key(str(env_file)), "synthetic-test-secret")


class ProbeRun(unittest.IsolatedAsyncioTestCase):
    async def test_fake_api_probe_measures_and_cleans_every_test_key(self):
        fake = FakeOpenRouter()
        # Patch only the transport constructors used by management and inference probes.
        from masqai.custody import openrouter
        from unittest.mock import patch as mock_patch

        original_init = openrouter.OpenRouterKeys.__init__

        def fake_init(instance, management_key, **kwargs):
            original_init(instance, management_key, transport=fake.transport)

        args = argparse.Namespace(workspace=FAKE_WORKSPACE, samples=2, rate_minutes=0, rate_interval=10,
                                  execute=True, confirm_budget=True, check_cleanup=False)
        with mock_patch.object(openrouter.OpenRouterKeys, "__init__", fake_init), \
             mock_patch.object(enigma_probe, "probe_key", new=AsyncMock(side_effect=[True, False, True, False])):
            report = await enigma_probe.run(args, FAKE_MGMT_KEY)
        self.assertEqual(len(report["samples"]), 2)
        self.assertTrue(report["workspace_budget_present"])
        self.assertEqual(fake.keys, {})
        self.assertNotIn(FAKE_MGMT_KEY, str(report))

    async def test_cleanup_check_counts_only_probe_names(self):
        fake = FakeOpenRouter()
        fake.add_key("unrelated-key")
        fake.add_key("enigma-probe-leftover")
        from masqai.custody import openrouter
        from unittest.mock import patch as mock_patch

        original_init = openrouter.OpenRouterKeys.__init__

        def fake_init(instance, management_key, **kwargs):
            original_init(instance, management_key, transport=fake.transport)

        args = argparse.Namespace(workspace=FAKE_WORKSPACE, samples=1, rate_minutes=0, rate_interval=10,
                                  execute=False, confirm_budget=False, check_cleanup=True)
        with mock_patch.object(openrouter.OpenRouterKeys, "__init__", fake_init):
            report = await enigma_probe.run(args, FAKE_MGMT_KEY)
        self.assertEqual(report["probe_named_keys_remaining"], 1)


if __name__ == "__main__":
    unittest.main()
