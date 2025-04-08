import os
import logging
import traceback

# Configure detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def check_database():
    """Check database connection and create tables if they don't exist"""
    try:
        print("Importing modules...")
        try:
            from app import app, db, User, APISettings
            print("Modules imported successfully")
        except ImportError as e:
            print(f"Error importing modules: {str(e)}")
            traceback.print_exc()
            return False
        
        print("Checking database configuration...")
        with app.app_context():
            print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
            
            # Check if database file exists for SQLite
            if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:///'):
                db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
                print(f"SQLite database path: {db_path}")
                if os.path.exists(db_path):
                    print("Database file exists")
                else:
                    print("Database file does not exist yet - will be created")
            
            # Create tables
            print("Creating database tables...")
            db.create_all()
            print("Tables created successfully")
            
            # Check if tables exist
            user_count = User.query.count()
            print(f"User count: {user_count}")
            
            # Check if APISettings table exists
            settings_count = APISettings.query.count()
            print(f"API settings count: {settings_count}")
            
            return True
    except Exception as e:
        print(f"Database error: {str(e)}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Starting database check...")
    success = check_database()
    if success:
        print("Database check completed successfully")
    else:
        print("Database check failed, see logs for details") 