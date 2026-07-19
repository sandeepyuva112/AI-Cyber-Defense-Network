from __future__ import annotations


def approximate_tokens(text: str) -> int:
    """Cheap heuristic token estimator.

    We avoid adding tokenization deps. Roughly: tokens ~ chars/4 for English-ish text.
    """

    if not text:
        return 0
    return max(1, len(text) // 4)


def truncate_to_token_budget(text: str, max_input_tokens: int) -> str:
    """Truncate input text to fit an approximate token budget."""

    if not text:
        return text
    if approximate_tokens(text) <= max_input_tokens:
        return text

    # Truncate by characters conservatively.
    # If tokens ~ chars/4 => chars ~ tokens*4
    max_chars = max_input_tokens * 4
    return text[:max_chars]

