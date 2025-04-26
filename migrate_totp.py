# migrations/add_password_health_tables.py
import sys
import os
from datetime import datetime
from sqlalchemy import create_engine, text

# Get database URL from environment variable
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    print("Error: DATABASE_URL environment variable not set")
    sys.exit(1)

# Create engine
engine = create_engine(database_url)

# SQL for creating the password history table
create_password_history_table_sql = """
CREATE TABLE IF NOT EXISTS password_history (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
"""

# SQL for creating the password health table
create_password_health_table_sql = """
CREATE TABLE IF NOT EXISTS password_health (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL UNIQUE,
    strength_score INTEGER DEFAULT 0,
    has_been_breached BOOLEAN DEFAULT FALSE,
    is_common BOOLEAN DEFAULT FALSE,
    last_changed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    days_until_expiry INTEGER,
    reused BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_health_user_id ON password_health(user_id);
"""

try:
    # Execute the SQL
    with engine.connect() as conn:
        conn.execute(text(create_password_history_table_sql))
        conn.execute(text(create_password_health_table_sql))
        conn.commit()
    
    print("Successfully created password health tables")
except Exception as e:
    print(f"Error creating password health tables: {e}")
    sys.exit(1)