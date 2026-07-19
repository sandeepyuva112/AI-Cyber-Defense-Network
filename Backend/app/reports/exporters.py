from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from typing import Any

from app.reports.exporters_html import render_html
from app.reports.exporters_json import export_json


class Exporter(ABC):
    @abstractmethod
    def export(self, report_obj: Any) -> Any:
        raise NotImplementedError


class JSONExporter(Exporter):
    def export(self, report_obj: Any) -> dict[str, Any]:
        return export_json(report_obj)


class HTMLExporter(Exporter):
    def export(self, report_obj: Any) -> str:
        return render_html(report_obj)


class PDFExporter(Exporter):
    def export(self, report_obj: Any) -> bytes:
        # We render HTML and convert to PDF.
        # Implementation uses WeasyPrint (lightweight, actively maintained).
        from weasyprint import HTML

        html = render_html(report_obj)
        pdf_bytes = HTML(string=html, base_url=".").write_pdf()
        return pdf_bytes


def export_to_base64(pdf_bytes: bytes) -> str:
    return base64.b64encode(pdf_bytes).decode("ascii")

