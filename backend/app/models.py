from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    full_name = Column(String(120), nullable=False)
    email = Column(String(320), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    theme = Column(String(20), nullable=False, default="dark")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")
    refresh_sessions = relationship(
        "RefreshSession", back_populates="user", cascade="all, delete-orphan"
    )


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    description = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    project_id = Column(
        Integer, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    filename = Column(String(255), nullable=False)
    language = Column(String(40), nullable=False, default="python")
    status = Column(String(30), nullable=False, default="completed")
    summary = Column(Text, nullable=False, default="")
    findings_json = Column(Text, nullable=False, default="[]")
    scanners_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    owner = relationship("User", back_populates="scans")
    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("ScanReport", back_populates="scan", cascade="all, delete-orphan")


Index("ix_scans_owner_created", Scan.owner_id, Scan.created_at)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(80), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    file = Column(String(1024), nullable=False)
    line = Column(Integer, nullable=False, default=1)
    snippet = Column(Text, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    recommendation = Column(Text, nullable=False, default="")
    source = Column(String(80), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    scan = relationship("Scan", back_populates="findings")


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    format = Column(String(20), nullable=False, default="json")
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    scan = relationship("Scan", back_populates="reports")


class RefreshSession(Base):
    __tablename__ = "refresh_sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    user_agent = Column(String(512), nullable=True)

    user = relationship("User", back_populates="refresh_sessions")


class Activity(Base):
    __tablename__ = "activity"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(80), nullable=False)
    description = Column(String(512), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

