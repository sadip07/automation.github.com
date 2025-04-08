# Content Automation Tool

A powerful content automation dashboard that generates AI content, publishes to WordPress, and shares on social media platforms.

## Features

- **AI Content Generation**: Create high-quality content with AI using customizable prompts and word counts
- **Keyword Batch Processing**: Upload a list of keywords to generate content for each one automatically
- **Rich Text Editor**: Edit generated content with Quill.js rich text editor
- **WordPress Integration**: Publish content directly to WordPress sites
- **Social Media Sharing**: Share content on Twitter/X, Facebook, Instagram, and Pinterest
- **Modern UI**: Dark/light theme toggle, responsive design, and intuitive navigation
- **Scheduling**: Schedule content generation and publishing tasks
- **User Authentication**: Secure login system with role-based access control (Admin/User)
- **Article Management**: View, edit, and manage generated articles with a modern interface
- **Error Handling**: Automatic retries for failed API calls with real-time status updates

## Authentication System

The application now includes a complete user authentication system:

- **Secure Login**: Password hashing with bcrypt
- **Role-Based Access**: Admin and User roles with different permissions
- **User Management**: Admins can create, view, and delete users
- **Profile Management**: Users can update their email and password
- **Test Account**: A default admin account is available for testing
  - Username: `sadip007`
  - Password: `sadip007`
  - Role: `Admin`

## Article Generation

### Batch Processing
1. Navigate to the "Content" section
2. Create a text file with one keyword per line
3. Upload the file using the "Choose File" button
4. Set your desired word count and prompt template
5. Click "Process Keywords" to start generation
6. Monitor progress in real-time in the Status Log

### Article Management
1. View all generated articles in the "Articles" section
2. Edit article title, content, and status
3. Delete articles as needed
4. Track article status (draft, published, failed)
5. View generation history and timestamps

### Error Handling
- Automatic retries (3 attempts) for failed API calls
- 10-second delay between retries
- Detailed error messages in the Status Log
- Failed articles marked with error details

## Setup Instructions

### Prerequisites

- Python 3.7+
- Node.js and npm (optional, for frontend development)
- API keys for:
  - Google Gemini API
  - Social media platforms
  - WordPress
- Database (SQLite for development, PostgreSQL for production)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/content-automation-tool.git
   cd content-automation-tool
   ```

2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Add your API keys and credentials

4. Initialize the database and create the test admin user:
   ```
   python init_db.py
   ```

5. Start the Flask backend:
   ```
   python app.py
   ```

6. Access the application at http://localhost:5000

### Database Configuration

#### Development (SQLite)
The default configuration uses SQLite for local development:
```
DATABASE_URL=sqlite:///users.db
```

#### Production (PostgreSQL on Heroku or AWS RDS)
For production, use a PostgreSQL database:
```
DATABASE_URL=postgresql://username:password@host:port/database
```

When deploying to Heroku, set the `DATABASE_URL` config var, and Heroku will automatically use the PostgreSQL add-on.

## Usage

### Authentication

1. Navigate to the login page
2. Enter your credentials (use the test account or create a new user)
3. Access features based on your role permissions

### User Management (Admin Only)

1. Log in as an admin user
2. Navigate to your profile page
3. Use the "Manage Users" option to view all users
4. Create new users with the "Add New User" button
5. Delete users as needed from the user list

### Content Generation

1. Navigate to the "Content" section
2. Enter a prompt in the input field
3. Select desired word count
4. Click "Generate Content"
5. Edit the content if needed
6. Enter a title and publish to WordPress or share on social media

### Batch Keyword Processing

1. Create a text file with one keyword per line
2. Upload the file in the "Keyword File Upload" section
3. Select desired word count and delay between posts
4. Click "Process Keywords"
5. Monitor the progress on the batch progress bar

## Deployment to Heroku

1. Create a Heroku account and install the Heroku CLI
2. Login to the Heroku CLI:
   ```
   heroku login
   ```

3. Create a new Heroku app:
   ```
   heroku create your-app-name
   ```

4. Add the PostgreSQL add-on:
   ```
   heroku addons:create heroku-postgresql:hobby-dev
   ```

5. Set environment variables:
   ```
   heroku config:set SECRET_KEY=your-secret-key
   heroku config:set GOOGLE_GEMINI_API_KEY=your-gemini-key
   heroku config:set OPENAI_API_KEY=your-openai-key
   # Add other required environment variables
   ```

6. Deploy the app:
   ```
   git push heroku main
   ```

7. The database will be automatically initialized during the first deployment.

## Security Considerations

- All passwords are hashed using bcrypt before storage
- Flask-Login manages user sessions securely
- Admin-only routes are protected with custom decorators
- Environment variables are used for sensitive credentials
- PostgreSQL is recommended for production deployments
- File uploads are validated and sanitized
- API keys are never exposed in client-side code

## License

MIT License 