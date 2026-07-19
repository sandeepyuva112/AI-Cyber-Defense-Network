from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, status


class ApiError(HTTPException):
    """Base class for typed API errors."""


def not_found(detail: str) -> ApiError:
    return ApiError(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def bad_request(detail: str) -> ApiError:
    return ApiError(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

