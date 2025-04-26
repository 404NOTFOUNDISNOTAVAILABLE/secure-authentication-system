import os
import logging
from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Get PostgreSQL connection details from environment variables
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    logger.warning("DATABASE_URL environment variable not found. Falling back to SQLite.")
    SQLALCHEMY_DATABASE_URL = "sqlite:///./secure_auth.db"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    logger.info("Connecting to PostgreSQL database")
    # Create engine with PostgreSQL connection string
    engine = create_engine(
        DATABASE_URL,
        pool_size=5,
        max_overflow=10,
        pool_timeout=30,
        pool_recycle=1800,  # Recycle connections after 30 minutes
        echo=False  # Set to True for SQL query logging
    )

    # Add event listeners for connection debugging if needed
    @event.listens_for(engine, "connect")
    def connect(dbapi_connection, connection_record):
        logger.info("Database connection established")

    @event.listens_for(engine, "checkout")
    def checkout(dbapi_connection, connection_record, connection_proxy):
        logger.debug("Database connection checked out")

    @event.listens_for(engine, "checkin")
    def checkin(dbapi_connection, connection_record):
        logger.debug("Database connection checked in")

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for declarative models
Base = declarative_base()

def verify_db_connection():
    """
    Verify database connection is working.
    Returns True if connection is successful, False otherwise.
    """
    try:
        # Test the connection
        with engine.connect() as connection:
            connection.execute("SELECT 1")
            logger.info("Database connection verified successfully")
            return True
    except Exception as e:
        logger.error(f"Database connection verification failed: {e}")
        return False

def init_db():
    """
    Initialize the database by creating all tables.
    This should be called at application startup.
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise