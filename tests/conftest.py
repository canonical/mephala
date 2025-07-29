"""
Global test fixtures.

• Injects a dummy OPENAI_API_KEY so Agent.__init__ succeeds.
• Stubs _make_request so no real network traffic happens.
"""
import os
import pytest
from mephala.ai.agent import Agent

@pytest.fixture(autouse=True)
def _stub_openai(monkeypatch):
    # 1. fake credentials
    os.environ.setdefault("OPENAI_API_KEY", "unit-test-key")

    # 2. short-circuit the outbound call
    def _fake_make_request(self, _prompt: str, **_kw):
        # add a predictable assistant response so later code that accesses
        # self._messages[-1]["content"] still works.
        self._messages.append(
            {"role": "assistant", "content": "stubbed response"}
        )
        return "stubbed response"

    monkeypatch.setattr(Agent, "_make_request", _fake_make_request)

    # 3. yield control to the test
    yield

    # 4. clean up the singleton so state does not leak between tests
    from mephala.ai.agent import _SingletonMeta
    _SingletonMeta._instance = None      # type: ignore[attr-defined]
