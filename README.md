# Secure Password Manager

A secure password manager built with Python (FastAPI) backend and Next.js frontend. The password manager uses strong encryption (AES-GCM) and secure key derivation (PBKDF2) to protect your passwords (derived from CS 255 Winter 2025 taught by Dan Boneh).

## Features

- Secure password storage using AES-GCM encryption
- PBKDF2 key derivation for master password
- Modern web interface with Next.js and TailwindCSS
- JWT-based authentication
- Password visibility toggle
- Easy password management (add, view, delete)

## Project Structure

```
password-manager/
├── backend/
│   ├── main.py              # FastAPI backend
│   ├── password_manager.py  # Core password manager logic
│   ├── util.py             # Utility functions
│   └── requirements.txt     # Python dependencies
└── frontend/
    ├── app/                 # Next.js application
    ├── public/             # Static assets
    └── package.json        # Node.js dependencies
```

## Setup

### Backend

1. Create a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. Run the backend server:
   ```bash
   uvicorn main:app --reload
   ```

### Frontend

1. Install Node.js dependencies:
   ```bash
   cd frontend
   npm install
   ```

2. Create a `.env.local` file:
   ```
   NEXTAUTH_URL=http://localhost:3000
   NEXTAUTH_SECRET=your-secret-key
   BACKEND_URL=http://localhost:8000
   ```

3. Run the development server:
   ```bash
   npm run dev
   ```

## Deployment

### Backend

1. Deploy the FastAPI backend to a cloud provider of your choice (e.g., Heroku, DigitalOcean, AWS)
2. Set up environment variables for production
3. Configure CORS settings for your production domain

### Frontend (Vercel)

1. Push your code to a Git repository
2. Connect your repository to Vercel
3. Configure the following environment variables in Vercel:
   - `NEXTAUTH_URL`: Your production URL
   - `NEXTAUTH_SECRET`: A secure random string
   - `BACKEND_URL`: Your backend API URL

4. Deploy!

## Security Considerations

- The master password is never stored, only used for key derivation
- Passwords are encrypted using AES-GCM with unique IVs
- PBKDF2 with 100,000 iterations is used for key derivation
- All cryptographic operations use the PyCryptodome library
- Frontend uses secure HttpOnly cookies for session management
- CORS is properly configured to prevent unauthorized access

## Development

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License 
