from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    email: EmailStr
    theme: str
    created_at: datetime


class RegisterIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    terms_accepted: bool

    @field_validator("full_name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if len(normalized) < 2:
            raise ValueError("Enter your full name.")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not any(char.islower() for char in value):
            raise ValueError("Password must include a lowercase letter.")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must include an uppercase letter.")
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must include a number.")
        return value

    @field_validator("terms_accepted")
    @classmethod
    def validate_terms(cls, value: bool) -> bool:
        if not value:
            raise ValueError("You must accept the terms to register.")
        return value


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    remember_me: bool = False


class ProfileUpdateIn(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    theme: str | None = Field(default=None, pattern="^(dark|light)$")


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class ProjectCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)


class ScanOut(BaseModel):
    id: int
    filename: str
    language: str
    status: str
    summary: str
    findings: list[dict[str, Any]]
    scanners: dict[str, Any] = Field(default_factory=dict)
    project_id: int | None = None
    created_at: str | None = None
