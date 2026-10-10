"""Create initial scheduler tables.

Revision ID: 0001_initial
Revises:
"""
from alembic import op
import sqlalchemy as sa

from app.models import Base

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    job_columns = {column["name"] for column in sa.inspect(bind).get_columns("jobs")}
    if "retry_config" not in job_columns:
        op.add_column(
            "jobs",
            sa.Column("retry_config", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        )


def downgrade():
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
