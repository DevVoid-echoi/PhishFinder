"""Claude call for page analysis. The key comes from ANTHROPIC_API_KEY (.env locally, never committed)."""
import anthropic

MODEL = "claude-haiku-5-5"  # small, fast and cheap: enough to extract facts from one page
TIMEOUT = 10.0  # seconds per attempt; the user is waiting for the warning
MAX_TOKENS = 1024  # thinking counts toward this limit; the JSON answer itself is short


class AIStopped(Exception):
    """Claude stopped before a complete answer (refusal, max_tokens)."""

def make_claude_extract(client=None):
    """Return llm_fn(system, user, schema) -> JSON string, the function analyze_page expects."""
    client = client or anthropic.Anthropic(timeout=TIMEOUT, max_retries=1)

    def claude_extract(system: str, user: str, schema: dict) -> str:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": "low", "format": {"type": "json_schema", "schema": schema}},
        )
        # A refused or cut-off answer may not follow the schema
        if response.stop_reason != "end_turn":
            raise AIStopped(response.stop_reason)
        # Thinking blocks may come first: read the answer by type, not by position
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise AIStopped("no text block")
        return text

    return claude_extract
