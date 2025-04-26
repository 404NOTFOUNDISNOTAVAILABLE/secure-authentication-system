import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

# Load environment variables
load_dotenv()

# Get database URL
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("ERROR: DATABASE_URL environment variable not found!")
    exit(1)

print(f"Attempting to connect to Neon database...")

try:
    # Create engine
    engine = create_engine(DATABASE_URL)
    
    # Test connection
    with engine.connect() as connection:
        result = connection.execute(text("SELECT version()"))
        version = result.scalar()
        print(f"Connection successful! PostgreSQL version: {version}")
        
except Exception as e:
    print(f"Connection error: {e}")