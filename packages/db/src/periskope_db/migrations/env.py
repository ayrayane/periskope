"""Alembic runs plain SQL migrations against PERISKOPE_DATABASE_URL."""
import os

from alembic import context
from sqlalchemy import create_engine

url = os.environ["PERISKOPE_DATABASE_URL"].replace("postgresql://", "postgresql+psycopg://", 1)
with create_engine(url).connect() as connection:
    context.configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()
