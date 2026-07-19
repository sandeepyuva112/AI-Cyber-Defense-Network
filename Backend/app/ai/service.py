from __future__ import annotations

from typing import Optional

from app.ai.openai_responses_client import OpenAIResponsesClient
from app.ai.prompt_templates import get_prompt_bundle
from app.ai.response_parser import AiResponseParser
from app.ai.token_management import truncate_to_token_budget
from app.ai.error_handling import AiServiceError
from app.schemas.ai_incident import AiIncidentReport
from app.schemas.ai_request import LogType

from app.detection.engine import DetectionEngine


class AiEngineService:

    def __init__(
        self,
        openai_client: Optional[OpenAIResponsesClient] = None,
        parser: Optional[AiResponseParser] = None,
    ) -> None:
        self.openai_client = openai_client or OpenAIResponsesClient()
        self.parser = parser or AiResponseParser()

    async def analyze_logs(
        self,
        *,
        correlation_id: str,
        log_type: LogType,
        log_text: str,
        max_output_tokens: int,
    ) -> AiIncidentReport:
        bundle = get_prompt_bundle()

        # Token management: cap input size
        # We pick a conservative input budget so we don't need exact tokenization.
        max_input_tokens = 3000
        safe_log_content = truncate_to_token_budget(log_text, max_input_tokens=max_input_tokens)

        prompt = bundle.analyze.format(
            log_type=log_type,
            correlation_id=correlation_id,
            log_content=safe_log_content,
        )

        raw = await self.openai_client.analyze(
            system=bundle.system,
            prompt=prompt,
            max_output_tokens=max_output_tokens,
        )

        # Best-effort extraction of the text from Responses API response.
        # Expected: output content in data['output'][...]['content'][...]['text']
        model_text = None
        if isinstance(raw, dict):
            out = raw.get("output")
            if isinstance(out, list) and out:
                # iterate and find a text field
                for item in out:
                    if not isinstance(item, dict):
                        continue
                    content = item.get("content")
                    if isinstance(content, list) and content:
                        for c in content:
                            if isinstance(c, dict) and "text" in c:
                                model_text = c["text"]
                                break
                    if model_text:
                        break

        if model_text is None:
            model_text = raw

        # Deterministic detection pass (no existing-code removal)
        deterministic = DetectionEngine()
        try:
            det_report = deterministic.analyze(
                correlation_id=correlation_id,
                log_type=str(log_type),
                log_text=safe_log_content,
            )
        except Exception:
            det_report = None

        # If deterministic engine produced findings, return them directly (Option 1).
        if det_report is not None and det_report.suspicious_activities:
            return det_report

        try:
            return self.parser.parse_incident_report(model_text, correlation_id, log_type)
        except Exception as e:
            raise AiServiceError(
                message="Failed to parse model response into incident report",
                code="ai_parse_error",
                details=str(e),
            )


