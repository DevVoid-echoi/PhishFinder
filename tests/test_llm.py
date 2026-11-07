"""Tests for the Claude call. A fake client stands in for the API: no key, no network, no cost."""
from types import SimpleNamespace as NS

import pytest

from app.llm import MODEL, AIStopped, make_claude_extract
from app.page_analysis import AI_SCHEMA, analyze_page
from tests.test_page_analysis import PHISH_HTML, PHISH_URL


class FakeMessages:
    def __init__(self, response):
        self.response, self.calls = response, []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response

def fake_client(stop_reason="end_turn", text='{"x": 1}'):
    content = [NS(type="thinking", thinking=""), NS(type="text", text=text)]
    return NS(messages=FakeMessages(NS(stop_reason=stop_reason, content=content)))

def test_sends_the_schema_and_returns_the_text_block():
    client = fake_client()
    assert make_claude_extract(client)("system", "page", AI_SCHEMA) == '{"x": 1}'
    call = client.messages.calls[0]
    assert (call["model"], call["system"]) == (MODEL, "system")
    assert call["messages"] == [{"role": "user", "content": "page"}]
    assert call["output_config"]["format"] == {"type": "json_schema", "schema": AI_SCHEMA}

@pytest.mark.parametrize("reason", ["refusal", "max_tokens"])
def test_incomplete_answer_raises(reason):
    with pytest.raises(AIStopped):
        make_claude_extract(fake_client(stop_reason=reason))("system", "page", AI_SCHEMA)

def test_answer_without_text_raises():
    client = NS(messages=FakeMessages(NS(stop_reason="end_turn", content=[])))
    with pytest.raises(AIStopped):
        make_claude_extract(client)("system", "page", AI_SCHEMA)

def test_refusal_keeps_the_rules():
    r = analyze_page(PHISH_HTML, PHISH_URL, make_claude_extract(fake_client(stop_reason="refusal")))
    assert r["ai_summary"] is None
    assert "page_brand_login" in {x["rule"] for x in r["reasons"]}
