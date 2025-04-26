from database import engine
import models

def drop_tables():
    print("Dropping all tables...")
    models.Base.metadata.drop_all(bind=engine)
    print("All tables dropped successfully!")

if __name__ == "__main__":
    drop_tables()