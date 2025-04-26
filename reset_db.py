from database import engine
import models

def reset_db():
    print("Dropping all tables...")
    models.Base.metadata.drop_all(bind=engine)
    print("All tables dropped successfully!")
    
    print("Creating all tables...")
    models.Base.metadata.create_all(bind=engine)
    print("All tables created successfully!")

if __name__ == "__main__":
    reset_db()