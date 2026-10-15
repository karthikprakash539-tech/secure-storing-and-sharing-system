from config import Config
from supabase import create_client

client = create_client(
    Config.SUPABASE_URL,
    Config.SUPABASE_SECRET_KEY,
)

response = client.storage.from_(
    Config.SUPABASE_BUCKET
).list("", {"limit": 1})

print("Supabase Storage connection successful.")
print("Bucket:", Config.SUPABASE_BUCKET)
print("Objects returned:", len(response))