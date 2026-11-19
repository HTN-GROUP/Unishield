import os
import psycopg2
from dotenv import load_dotenv

# .env file se variables load karein
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

def test_connection():
    try:
        # Neon PostgreSQL se connection establish karein
        connection = psycopg2.connect(DATABASE_URL)
        cursor = connection.cursor()
        
        # Simple query run karke check karein
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()
        print(f"Successfully connected to Neon PostgreSQL! Database version: {db_version[0]}")
        
        cursor.close()
        connection.close()
    except Exception as error:
        print(f"Connection failed: {error}")

if __name__ == "__main__":
    test_connection()