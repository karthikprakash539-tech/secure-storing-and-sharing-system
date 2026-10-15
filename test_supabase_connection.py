from config import Config
from db import get_db


if Config.DATABASE_BACKEND != "supabase":
    raise SystemExit("Set DATABASE_BACKEND=supabase before running this check.")

Config.validate()

with get_db() as connection:
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_schema()")
        database_name, schema_name = cursor.fetchone().values()

print("Supabase PostgreSQL connection successful.")
print(f"Database: {database_name}; schema: {schema_name}")