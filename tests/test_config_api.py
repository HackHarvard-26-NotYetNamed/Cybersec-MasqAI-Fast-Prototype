"""Config panel API: per-field errors, cross-field references, meta and env status endpoints."""
import os
import unittest
from unittest.mock import patch

import httpx

from masqai.app import create_app
from masqai.config import GatewayConfig, ModelRoute, ProviderConfig, SecurityModelConfig, DetectorConfig


def config():
    return GatewayConfig(providers=[ProviderConfig(name="p", base_url="http://fake")], default_route=ModelRoute(provider="p"),
                         security=SecurityModelConfig(enabled=False), detectors=DetectorConfig(detect_host_identifiers=False))


class ConfigApi(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(config())), base_url="http://localhost")

    async def asyncTearDown(self):
        await self.client.aclose()

    async def post(self, **changes):
        body = (await self.client.get("/api/config")).json()
        body.update(changes)
        return await self.client.post("/api/config", json=body)

    async def errors(self, **changes):
        response = await self.post(**changes)
        self.assertEqual(response.status_code, 400)
        return {".".join(map(str, e["loc"])): e["msg"] for e in response.json()["errors"]}

    async def test_round_trip_unchanged(self):
        self.assertEqual((await self.post()).status_code, 200)

    async def test_field_errors_carry_locations(self):
        errors = await self.errors(providers=[{"name": "p", "base_url": "fake", "api_key_env": "sk-abc-123"}])
        self.assertIn("providers.0.base_url", errors)
        self.assertIn("providers.0.api_key_env", errors)

    async def test_reference_errors_point_at_field(self):
        errors = await self.errors(routes={"m": {"provider": "nope"}})
        self.assertEqual(list(errors), ["routes.m.provider"])
        errors = await self.errors(security={"enabled": True, "provider": "nope", "model": "x"})
        self.assertIn("security.provider", errors)
        errors = await self.errors(providers=[{"name": "p", "base_url": "http://a"}, {"name": "p", "base_url": "http://b"}])
        self.assertIn("providers.1.name", errors)

    async def test_custom_values_validated(self):
        errors = await self.errors(detectors={"detect_host_identifiers": False, "custom_values": [{"type": "bad type", "value": "ab"}]})
        self.assertIn("detectors.custom_values.0.type", errors)
        self.assertIn("detectors.custom_values.0.value", errors)

    async def test_port_cannot_change_at_runtime(self):
        self.assertIn("port", await self.errors(port=9999))

    async def test_failed_apply_changes_nothing(self):
        await self.errors(upstream_timeout_seconds=-1)
        self.assertEqual((await self.client.get("/api/config")).json()["upstream_timeout_seconds"], 180)

    async def test_blank_strings_become_null(self):
        response = await self.post(default_route={"provider": "p", "model": ""}, security={"enabled": False, "provider": "", "model": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()["default_route"]["model"])
        self.assertIsNone(response.json()["security"]["provider"])

    async def test_meta(self):
        meta = (await self.client.get("/api/config/meta")).json()
        self.assertIn("authorization", meta["always_dropped_headers"])
        self.assertIn("EMAIL", meta["detector_patterns"])
        self.assertIn("MasqAI", meta["default_security_prompt"])
        self.assertIsInstance(meta["features"], dict)

    async def test_env_status_never_returns_value(self):
        with patch.dict(os.environ, {"MASQ_TEST_SECRET": "sk-very-secret"}):
            response = await self.client.get("/api/env/MASQ_TEST_SECRET")
        self.assertEqual(response.json(), {"name": "MASQ_TEST_SECRET", "set": True})
        self.assertNotIn("sk-very-secret", response.text)
        self.assertFalse((await self.client.get("/api/env/MASQ_UNSET_VAR_XYZ")).json()["set"])
        self.assertEqual((await self.client.get("/api/env/not-a-name")).status_code, 400)


if __name__ == "__main__":
    unittest.main()
