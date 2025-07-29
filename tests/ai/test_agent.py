import pytest
from mephala.ai.agent import Agent

@pytest.fixture(autouse=True)
def stub_openai(monkeypatch):
    def fake_ask(self, prompt, **kw):
        if kw.get("output_format"):
            # minimal shape Backporter expects
            return {"metadata": {}}
        return "```python\nprint('hello world')\n```"
    monkeypatch.setattr(Agent, "ask", fake_ask)
    yield

def test_session_cleared_after_call():
    ag = Agent()
    ag.ask("dummy prompt")
    # .ask() calls new_session() when keep_session=False
    assert ag._messages == []
