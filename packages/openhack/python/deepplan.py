#!/usr/bin/env python3
"""deepagents planning harness for the OpenHack manager tier.

Reads ``{"prompt": str, "model": str|null}`` JSON on stdin, runs the prompt
through the vendored deepagents harness (``create_deep_agent``), and prints the
agent's final answer to stdout. Errors are reported on a final
``__DEEPPLAN_ERROR__:`` line so the TypeScript bridge can surface them (nothing
is swallowed silently).

Model selection: ``init_chat_model`` (LangChain) resolves provider strings like
``deepseek:deepseek-chat`` or ``anthropic:claude-sonnet-4`` using the standard
provider environment variables (DEEPSEEK_API_KEY, ANTHROPIC_API_KEY, ...).
"""

from __future__ import annotations

import json
import sys


def _emit_error(message: str) -> None:
    print(f"__DEEPPLAN_ERROR__: {message}", file=sys.stdout)


def _resolve_model(model: str | None):
    from langchain.chat_models import init_chat_model

    if not model:
        return None
    if ":" in model:
        provider, _, name = model.partition(":")
        return init_chat_model(name, model_provider=provider)
    return init_chat_model(model)


def main() -> int:
    try:
        request = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError as exc:
        _emit_error(f"invalid request JSON: {exc}")
        return 2

    prompt = request.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        _emit_error("request is missing a non-empty 'prompt'")
        return 2

    try:
        from deepagents import create_deep_agent
    except Exception as exc:  # noqa: BLE001 — surfaced verbatim to the bridge
        _emit_error(f"deepagents import failed (is the venv bootstrapped?): {exc}")
        return 2

    try:
        model = _resolve_model(request.get("model"))
        agent = create_deep_agent(
            model=model,
            system_prompt=(
                "You are a pentest engagement phase-manager. Decide which objectives "
                "to dispatch this round. Answer with ONLY the JSON object the task "
                "requests — no prose, no markdown fences."
            ),
        )
        result = agent.invoke({"messages": [{"role": "user", "content": prompt}]})
        messages = result.get("messages", []) if isinstance(result, dict) else []
        text = ""
        for message in reversed(messages):
            content = getattr(message, "content", None) or (message.get("content") if isinstance(message, dict) else None)
            if isinstance(content, str) and content.strip():
                text = content
                break
            if isinstance(content, list):
                parts = [part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text"]
                joined = "".join(parts).strip()
                if joined:
                    text = joined
                    break
        if not text.strip():
            _emit_error("deepagents produced no text content")
            return 1
        print(text)
        return 0
    except Exception as exc:  # noqa: BLE001 — surfaced verbatim to the bridge
        _emit_error(f"{type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
