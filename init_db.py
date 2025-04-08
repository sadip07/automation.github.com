from app import app, db, User, Article, bcrypt
import os

def init_db():
    # Create the database tables
    with app.app_context():
        db.create_all()
        
        # Check if the admin user already exists
        admin_user = User.query.filter_by(username='sadip007').first()
        
        # Create admin user if it doesn't exist
        if not admin_user:
            hashed_password = bcrypt.generate_password_hash('sadip007').decode('utf-8')
            admin = User(
                username='sadip007',
                email='admin@example.com',
                password=hashed_password,
                role='Admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user 'sadip007' created successfully!")
        else:
            print("Admin user 'sadip007' already exists.")
            
        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join(app.root_path, 'uploads')
        if not os.path.exists(uploads_dir):
            os.makedirs(uploads_dir)
            print("Created uploads directory")

if __name__ == '__main__':
    init_db() 