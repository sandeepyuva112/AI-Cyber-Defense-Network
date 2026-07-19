from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from app.schemas.ai_incident import AiIncidentReport


def _extract_json(text: str) -> str:
    """Extract the first JSON object from text.

    Handles common cases where the model might include text before/after the JSON.
    Uses a brace-depth scan to avoid accidentally capturing multiple JSON blocks.
    """

    text = text.strip()
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in model output")

    depth = 0
    in_str = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]

        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue

        if ch == '"':
            in_str = True
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    raise ValueError("No complete JSON object found in model output")



class AiResponseParser:
    def parse_incident_report(self, model_output: Any, correlation_id: str, log_type: str) -> AiIncidentReport:
        if isinstance(model_output, dict):
            raw = model_output
        else:
            raw_text = str(model_output)

            # Robust extraction: scan from first JSON object start and incrementally
            # try to decode until success.
            # Primary strategy: try to find a JSON object and decode.
            # Secondary strategy: strip everything outside the decoded JSON by scanning for a valid decode.
            try:
                # If the text contains an extra wrapper like "{\n{...}\n}",
                # search for the first valid JSON decode after the first '{'.
                start = raw_text.find("{")
                if start == -1:
                    raise ValueError("No JSON object found")

                raw = None
                last_end = raw_text.rfind("}")
                for end in range(last_end + 1, start + 1, -1):
                    candidate = raw_text[start:end]
                    if not candidate.endswith("}"):
                        continue
                    try:
                        raw = json.loads(candidate)
                        break
                    except json.JSONDecodeError:
                        continue

                if raw is None:
                    raw_json = _extract_json(raw_text)
                    raw = json.loads(raw_json)
            except Exception:
                start = raw_text.find("{")

                if start == -1:
                    raise

                # Try progressively smaller suffixes from the end.
                raw = None
                last_end = raw_text.rfind("}")
                for end in range(last_end + 1, start + 1, -1):
                    candidate = raw_text[start:end]
                    # Heuristic: candidate must contain closing brace.
                    if not candidate.endswith("}"):
                        continue
                    try:
                        raw = json.loads(candidate)
                        break
                    except json.JSONDecodeError:
                        continue

                # One more heuristic: if the JSON is wrapped by an extra "{ ... }" shell like "{\n{...}\n}",
                # attempt to remove an outer shell.
                if raw is None:
                    try:
                        outer = _extract_json(raw_text)
                        # If outer starts with "{" followed immediately by another "{", strip the first char.
                        if outer.startswith("{{"):
                            raw = json.loads(outer[1:])
                    except Exception:
                        pass

                if raw is None:
                    raise




        # Normalize mandatory fields that the model might omit
        raw.setdefault("incident_id", correlation_id)
        raw.setdefault("log_type", log_type)

        try:
            report = AiIncidentReport.model_validate(raw)
        except ValidationError as e:
            # Attach raw for troubleshooting
            raise ValueError(f"Model output does not match schema: {e}")

        report.raw = raw if isinstance(raw, dict) else {"value": raw}
        return report

