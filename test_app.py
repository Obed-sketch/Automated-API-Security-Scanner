"""End-to-end tests for the Automated API Security Scanner.

The HTTP transport is replaced with an in-memory fake API, so the suite
runs fully offline:  python -m pytest test_app.py
"""
import json
from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).parent / "app.py")
ORDER = {"id": "order-1001", "owner": "user-a", "total": 42}


class FakeResp:
    def __init__(self, status, payload, headers=None):
        self.status_code = status
        self._payload = payload
        self.headers = headers or {"Content-Type": "application/json"}
        self.content = json.dumps(payload).encode()
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


@pytest.fixture()
def fake_api(monkeypatch):
    state = {"bola": "vuln", "rate_limit_after": None, "rate_calls": 0, "verify_seen": []}

    def fake_request(method, url, headers=None, json=None, timeout=None,
                     allow_redirects=True, verify=True, **kw):
        state["verify_seen"].append(verify)
        auth = (headers or {}).get("Authorization", "")
        if "/api/orders/" in url:
            if state["bola"] == "vuln":
                return FakeResp(200, ORDER)
            oid = url.rsplit("/", 1)[-1]
            if auth == "Bearer token-a" and oid == "order-1001":
                return FakeResp(200, ORDER)
            return FakeResp(403, {"error": "forbidden"})
        if "/api/health" in url:
            state["rate_calls"] += 1
            if state["rate_limit_after"] and state["rate_calls"] > state["rate_limit_after"]:
                return FakeResp(429, {"error": "slow down"},
                                {"Content-Type": "application/json", "Retry-After": "30"})
            return FakeResp(200, {"ok": True})
        return FakeResp(404, {"error": "not found"})

    monkeypatch.setattr(requests, "request", fake_request)
    return state


def boot():
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    for cb in at.checkbox:
        if cb.label == "I am authorized to test this API":
            cb.set_value(True).run()
    assert not at.exception
    return at


def set_input(at, label, value):
    for el in list(at.text_input) + list(at.text_area):
        if el.label == label:
            el.set_value(value)
            return
    raise AssertionError(f"input not found: {label}")


def click(at, label):
    for b in at.button:
        if b.label == label:
            b.click().run()
            return
    raise AssertionError(f"button not found: {label}")


def bola_setup(at):
    set_input(at, "REST endpoint template", "https://staging.example.com/api/orders/{object_id}")
    set_input(at, "Identity A bearer token", "token-a")
    set_input(at, "Object ID owned by A", "order-1001")
    set_input(at, "Identity B bearer token", "token-b")
    set_input(at, "Object ID owned by B", "order-2002")


def test_authorization_gate():
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    assert any("Confirm authorization" in i.value for i in at.info)
    assert len(at.tabs) == 0


def test_bola_vulnerable_api_flagged(fake_api):
    at = boot()
    bola_setup(at)
    click(at, "Run BOLA comparison")
    assert any("Potential BOLA" in e.value for e in at.error)


def test_bola_protected_api_passes(fake_api):
    fake_api["bola"] = "fixed"
    at = boot()
    bola_setup(at)
    click(at, "Run BOLA comparison")
    assert any("No obvious BOLA" in s.value for s in at.success)


def test_http_endpoint_rejected(fake_api):
    at = boot()
    set_input(at, "REST endpoint template", "http://insecure.example.com/api/orders/{object_id}")
    set_input(at, "Object ID owned by A", "order-1001")
    set_input(at, "Object ID owned by B", "order-2002")
    click(at, "Run BOLA comparison")
    assert any("HTTPS" in e.value for e in at.error)


def test_rate_limit_stops_on_429(fake_api):
    fake_api["rate_limit_after"] = 2
    at = boot()
    set_input(at, "Target HTTPS endpoint", "https://staging.example.com/api/health")
    click(at, "Run rate-limit check")
    assert fake_api["rate_calls"] == 3  # stopped immediately after the 429
    assert any("Rate limiting was observed" in s.value for s in at.success)


def test_tls_verify_flag_reaches_transport(fake_api):
    at = boot()
    bola_setup(at)
    click(at, "Run BOLA comparison")
    assert fake_api["verify_seen"] and all(v is True for v in fake_api["verify_seen"])


def test_helpers():
    import re
    import time
    from datetime import datetime, timezone
    from typing import Any, Dict, Optional

    src = Path(APP).read_text()
    seg = src[src.index("def make_headers"):src.index("# ---------------------------- Sidebar")]
    ns = {"json": json, "time": time, "datetime": datetime, "timezone": timezone,
          "Any": Any, "Dict": Dict, "Optional": Optional, "requests": requests}
    exec(seg, ns)
    headers = ns["make_headers"]("Bearer token", "abc", {"X-Test": "1"})
    assert headers["Authorization"] == "Bearer abc" and headers["X-Test"] == "1"
    assert ns["parse_headers"]('{"A": "b"}') == {"A": "b"}
    with pytest.raises(ValueError):
        ns["parse_headers"]('{"A": 2}')
    body = ns["graphql_body"]('query { order(id: "{object_id}") }', "o-9", '{"id": "{object_id}"}')
    assert "o-9" in body["query"] and body["variables"] == {"id": "o-9"}
