"""Request validation (Pydantic). Length limits and character checks happen BEFORE any analysis."""
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from backend.utils.constants import MAX_BODY_CHARS


class AnalyzeRequest(BaseModel):
    sender: str = Field("", max_length=320)
    subject: str = Field("", max_length=500)
    body: str = Field("", max_length=MAX_BODY_CHARS)
    attachment_name: str = Field("", max_length=255)
    display_name: Optional[str] = Field(None, max_length=200)
    use_ml: bool = True

    @field_validator("attachment_name")
    @classmethod
    def _filename_only(cls, v: str) -> str:
        if re.search(r"[\\/\x00]", v):
            raise ValueError("attachment_name must be a plain filename (no path separators)")
        return v.strip()

    @model_validator(mode="after")
    def _not_empty(self):
        if not (self.sender.strip() or self.subject.strip() or self.body.strip()):
            raise ValueError("Provide at least one of: sender, subject, body")
        return self


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


class Credentials(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(..., min_length=8, max_length=128)
