# GidiGo Backend

The backend service for the GidiGo ride-hailing platform, built with Django and Django REST Framework. This service handles user authentication, ride management, real-time tracking, and all other server-side operations.

## 🛠️ Tech Stack

- **Framework**: Django 5.1.3
- **API**: Django REST Framework 3.15.2
- **Database**: PostgreSQL
- **Authentication**: JWT (Simple JWT)
- **Real-time**: Pusher
- **Documentation**: drf-yasg (Swagger/OpenAPI)
- **Security**: Argon2 Password Hashing
- **Email**: SMTP (Gmail)
- **File Storage**: WhiteNoise (Static Files)

## 📁 Project Structure

```
backend/
├── accounts/                 # User management app
│   ├── models.py            # User and session models
│   ├── serializers.py       # User-related serializers
│   ├── views.py             # Authentication views
│   └── urls.py              # User-related endpoints
├── rides/                   # Ride management app
│   ├── models.py            # Ride and location models
│   ├── serializers.py       # Ride-related serializers
│   ├── views.py             # Ride management views
│   └── urls.py              # Ride-related endpoints
├── gidigo_server/          # Project configuration
│   ├── settings.py          # Development settings
│   ├── settings_prod.py     # Production settings
│   ├── urls.py              # Main URL routing
│   └── wsgi.py              # WSGI configuration
├── requirements.txt        # Project dependencies
├── manage.py              # Django management script
└── .env                   # Environment variables
```

## 🚀 Setup and Installation

1. **Clone the Repository**

   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Set Up Virtual Environment**

   ```bash
   python -m venv env
   source env/bin/activate  # Unix/MacOS
   # or
   .\env\Scripts\activate  # Windows
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment**

   ```bash
   cp .env.example .env
   # Update .env with your configuration
   ```

5. **Database Setup**

   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create Superuser**

   ```bash
   python manage.py createsuperuser
   ```

7. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

## 🔑 Authentication

The backend uses JWT (JSON Web Tokens) for authentication with the following features:

- Token-based authentication (JWT)
- Token refresh mechanism
- Session management
- Password reset functionality
- Email verification

### Endpoints

- `POST /api/auth/register/`: User registration
- `POST /api/auth/login/`: User login
- `POST /api/auth/logout/`: User logout
- `POST /api/auth/token/refresh/`: Refresh access token
- `POST /api/auth/password/reset/`: Request password reset
- `POST /api/auth/password/reset/confirm/`: Confirm password reset
- `GET /api/auth/sessions/`: List active sessions
- `DELETE /api/auth/sessions/{id}/`: Terminate specific session

## 🚗 Ride Management

Handles all ride-related operations including:

- Ride requests
- Driver matching
- Real-time location updates
- Ride status management
- Fare calculation
- Rating system

### Endpoints

- `POST /api/rides/request/`: Create ride request
- `GET /api/rides/active/`: Get active ride
- `PATCH /api/rides/{id}/status/`: Update ride status
- `POST /api/rides/{id}/location/`: Update location
- `POST /api/rides/{id}/complete/`: Complete ride
- `POST /api/rides/{id}/rate/`: Rate ride
- `GET /api/rides/history/`: Get ride history

## 📱 Real-time Features

Real-time updates are handled through Pusher with the following channels:

- `private-user-{id}`: User-specific notifications
- `private-driver-{id}`: Driver location updates
- `private-ride-{id}`: Ride status updates

### Pusher Events

- `ride.requested`: New ride request
- `ride.accepted`: Ride accepted by driver
- `ride.started`: Ride started
- `ride.completed`: Ride completed
- `location.updated`: Driver location update

## 🔒 Security Features

- Argon2 password hashing
- Rate limiting
- CORS configuration
- Session management
- Request throttling
- XSS protection
- CSRF protection
- Secure cookie configuration

## 📊 Database Schema

Key models and their relationships:

- `CustomUser`: Extended user model
- `UserSession`: Session management
- `Ride`: Ride information
- `Location`: Location tracking
- `Rating`: User ratings
- `Notification`: System notifications

## 🚀 Deployment

### Prerequisites

- PostgreSQL database
- Python 3.8+
- Required environment variables

### Render Deployment

1. Connect GitHub repository
2. Configure environment variables
3. Set build command:
   ```bash
   ./build.sh
   ```
4. Set start command:
   ```bash
   gunicorn gidigo_server.wsgi:application
   ```

### Environment Variables

Required environment variables for production:

```
DJANGO_ENV=production
SECRET_KEY=your-secret-key
DATABASE_URL=postgres://user:password@host:5432/database_name
ALLOWED_HOSTS=your-domain.com
FRONTEND_URL=https://your-frontend-domain.com
PUSHER_APP_ID=your-app-id
PUSHER_KEY=your-key
PUSHER_SECRET=your-secret
PUSHER_CLUSTER=your-cluster
EMAIL_HOST_USER=your-email
EMAIL_HOST_PASSWORD=your-app-password
```

## 📝 API Documentation

API documentation is available at `/api/docs/` when the server is running. It provides:

- Interactive API documentation
- Request/response examples
- Authentication instructions
- Schema definitions

## 🧪 Testing

Run tests with:

```bash
python manage.py test
```

For coverage report:

```bash
coverage run manage.py test
coverage report
```

## 📚 Additional Resources

- [Django Documentation](https://docs.djangoproject.com/)
- [Django REST Framework](https://www.django-rest-framework.org/)
- [Pusher Documentation](https://pusher.com/docs)
- [Simple JWT Documentation](https://django-rest-framework-simplejwt.readthedocs.io/)
