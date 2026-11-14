"""Add user identity, owned projects, normalized findings, and sessions."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0001_identity_projects"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    existing = set(inspect(bind).get_table_names())

    if "users" not in existing:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("full_name", sa.String(length=120), nullable=False),
            sa.Column("email", sa.String(length=320), nullable=False),
            sa.Column("password_hash", sa.String(length=255), nullable=False),
            sa.Column("theme", sa.String(length=20), nullable=False, server_default="dark"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("email", name="uq_users_email"),
        )
        op.create_index("ix_users_email", "users", ["email"], unique=True)

    if "projects" not in existing:
        op.create_table(
            "projects",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(length=120), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_projects_owner_id", "projects", ["owner_id"])

    if "scans" not in existing:
        op.create_table(
            "scans",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True),
            sa.Column("filename", sa.String(length=255), nullable=False),
            sa.Column("language", sa.String(length=40), nullable=False, server_default="python"),
            sa.Column("status", sa.String(length=30), nullable=False, server_default="completed"),
            sa.Column("summary", sa.Text(), nullable=False, server_default=""),
            sa.Column("findings_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("scanners_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
    else:
        scan_columns = {column["name"] for column in inspect(bind).get_columns("scans")}
        with op.batch_alter_table("scans") as batch:
            if "owner_id" not in scan_columns:
                batch.add_column(sa.Column("owner_id", sa.Integer(), nullable=True))
                batch.create_foreign_key("fk_scans_owner_id_users", "users", ["owner_id"], ["id"], ondelete="CASCADE")
            if "project_id" not in scan_columns:
                batch.add_column(sa.Column("project_id", sa.Integer(), nullable=True))
                batch.create_foreign_key(
                    "fk_scans_project_id_projects", "projects", ["project_id"], ["id"], ondelete="SET NULL"
                )
            if "scanners_json" not in scan_columns:
                batch.add_column(sa.Column("scanners_json", sa.Text(), nullable=False, server_default="{}"))

    for name, columns in (
        ("ix_scans_owner_id", ["owner_id"]),
        ("ix_scans_project_id", ["project_id"]),
        ("ix_scans_owner_created", ["owner_id", "created_at"]),
    ):
        if name not in {index["name"] for index in inspect(bind).get_indexes("scans")}:
            op.create_index(name, "scans", columns)

    if "findings" not in existing:
        op.create_table(
            "findings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("rule_id", sa.String(length=80), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("file", sa.String(length=1024), nullable=False),
            sa.Column("line", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("snippet", sa.Text(), nullable=False, server_default=""),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("recommendation", sa.Text(), nullable=False, server_default=""),
            sa.Column("source", sa.String(length=80), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
        op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
        op.create_index("ix_findings_severity", "findings", ["severity"])

    if "scan_reports" not in existing:
        op.create_table(
            "scan_reports",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("format", sa.String(length=20), nullable=False, server_default="json"),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_scan_reports_scan_id", "scan_reports", ["scan_id"])

    if "refresh_sessions" not in existing:
        op.create_table(
            "refresh_sessions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("user_agent", sa.String(length=512), nullable=True),
        )
        op.create_index("ix_refresh_sessions_user_id", "refresh_sessions", ["user_id"])
        op.create_index("ix_refresh_sessions_token_hash", "refresh_sessions", ["token_hash"], unique=True)
        op.create_index("ix_refresh_sessions_expires_at", "refresh_sessions", ["expires_at"])

    if "activity" not in existing:
        op.create_table(
            "activity",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("action", sa.String(length=80), nullable=False),
            sa.Column("description", sa.String(length=512), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_activity_owner_id", "activity", ["owner_id"])


def downgrade() -> None:
    op.drop_table("activity")
    op.drop_table("refresh_sessions")
    op.drop_table("scan_reports")
    op.drop_table("findings")
    op.drop_index("ix_scans_owner_created", table_name="scans")
    op.drop_index("ix_scans_project_id", table_name="scans")
    op.drop_index("ix_scans_owner_id", table_name="scans")
    op.drop_table("scans")
    op.drop_table("projects")
    op.drop_table("users")
