"""change the length of share_code

Revision ID: 94fdcda2e83a
Revises: 64f4c0226b97
Create Date: 2023-12-07 16:46:19.319458

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = '94fdcda2e83a'
down_revision: Union[str, None] = '64f4c0226b97'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('share', 'share_code',
               existing_type=mysql.VARCHAR(length=6),
               type_=sa.String(length=8),
               existing_nullable=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('share', 'share_code',
               existing_type=sa.String(length=8),
               type_=mysql.VARCHAR(length=6),
               existing_nullable=False)
    op.create_table('celery_taskmeta',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('task_id', mysql.VARCHAR(length=155), nullable=True),
    sa.Column('status', mysql.VARCHAR(length=50), nullable=True),
    sa.Column('result', sa.BLOB(), nullable=True),
    sa.Column('date_done', mysql.DATETIME(), nullable=True),
    sa.Column('traceback', mysql.TEXT(), nullable=True),
    sa.Column('name', mysql.VARCHAR(length=155), nullable=True),
    sa.Column('args', sa.BLOB(), nullable=True),
    sa.Column('kwargs', sa.BLOB(), nullable=True),
    sa.Column('worker', mysql.VARCHAR(length=155), nullable=True),
    sa.Column('retries', mysql.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('queue', mysql.VARCHAR(length=155), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_0900_ai_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.create_index('task_id', 'celery_taskmeta', ['task_id'], unique=False)
    op.create_table('kombu_message',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('visible', mysql.TINYINT(display_width=1), autoincrement=False, nullable=True),
    sa.Column('timestamp', mysql.DATETIME(), nullable=True),
    sa.Column('payload', mysql.TEXT(), nullable=False),
    sa.Column('version', mysql.SMALLINT(), autoincrement=False, nullable=False),
    sa.Column('queue_id', mysql.INTEGER(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['queue_id'], ['kombu_queue.id'], name='FK_kombu_message_queue'),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_0900_ai_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.create_index('ix_kombu_message_visible', 'kombu_message', ['visible'], unique=False)
    op.create_index('ix_kombu_message_timestamp_id', 'kombu_message', ['timestamp', 'id'], unique=False)
    op.create_index('ix_kombu_message_timestamp', 'kombu_message', ['timestamp'], unique=False)
    op.create_table('kombu_queue',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('name', mysql.VARCHAR(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_0900_ai_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.create_index('name', 'kombu_queue', ['name'], unique=False)
    op.create_table('celery_tasksetmeta',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('taskset_id', mysql.VARCHAR(length=155), nullable=True),
    sa.Column('result', sa.BLOB(), nullable=True),
    sa.Column('date_done', mysql.DATETIME(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_0900_ai_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.create_index('taskset_id', 'celery_tasksetmeta', ['taskset_id'], unique=False)
    # ### end Alembic commands ###
