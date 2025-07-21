# WanderLanka User Service

A unified authentication service for both WanderLanka Web and Mobile applications, supporting role-based registration and login.

## Overview

This service provides authentication endpoints for:
- **Web App**: `transport` and `accommodation` providers
- **Mobile App**: `tourist` (mapped to `traveller`) and `guide` users

## Features

- ✅ **Role-based Authentication** - Different roles for web and mobile platforms
- ✅ **JWT Token Management** - Access and refresh tokens
- ✅ **Password Security** - Bcrypt hashing with 12 salt rounds
- ✅ **Rate Limiting** - Prevents brute force attacks
- ✅ **Input Validation** - Express-validator for request validation
- ✅ **MongoDB Integration** - User data persistence with indexing
- ✅ **CORS Support** - Configured for both web and mobile origins
- ✅ **Comprehensive Logging** - Request and error logging

## Architecture

### Platform Separation
- **Web Routes**: `/register`, `/login` - Traditional web app endpoints
- **Mobile Routes**: `/api/auth/*` - RESTful API endpoints for mobile

### User Roles Mapping
| Platform | Frontend Role | Backend Role | Description |
|----------|--------------|--------------|-------------|
| Web | `transport` | `transport` | Transportation service providers |
| Web | `accommodation` | `accommodation` | Hotel/accommodation providers |
| Mobile | `tourist` | `traveller` | Tourists exploring Sri Lanka |
| Mobile | `guide` | `guide` | Local guides and experts |

## API Endpoints

### Health Check
```
GET /health
```

### Web App Endpoints (Existing - Unchanged)
```
POST /register        - Web user registration
POST /login          - Web user login  
GET  /profile        - Get user profile (with token)
GET  /verify-token   - Verify JWT token
```

### Mobile App Endpoints (New)
```
POST /api/auth/signup      - Mobile user registration
POST /api/auth/login       - Mobile user login
POST /api/auth/logout      - Mobile user logout
POST /api/auth/refresh     - Refresh access token
GET  /api/auth/profile     - Get user profile
GET  /api/auth/verify-token - Verify JWT token
POST /api/auth/cleanup-tokens - Cleanup expired refresh tokens
```

## Request/Response Examples

### Mobile Registration
**POST** `/api/auth/signup`
```json
{
  "username": "john_doe",
  "email": "john@example.com", 
  "password": "StrongPass123",
  "role": "tourist"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": "64f8a...",
      "username": "john_doe",
      "email": "john@example.com",
      "role": "traveller",
      "avatar": null,
      "isActive": true,
      "emailVerified": false,
      "createdAt": "2023-09-06T...",
      "updatedAt": "2023-09-06T..."
    },
    "accessToken": "eyJhbGciOiJ...",
    "refreshToken": "eyJhbGciOiJ..."
  }
}
```

### Mobile Login
**POST** `/api/auth/login`
```json
{
  "identifier": "john_doe",
  "password": "StrongPass123"
}
```

**Response:** Same format as registration

### Token Refresh
**POST** `/api/auth/refresh`
```json
{
  "refreshToken": "eyJhbGciOiJ..."
}
```

## Database Schema

### User Model
```javascript
{
  username: String (unique, 3-30 chars),
  email: String (unique, normalized),
  password: String (bcrypt hashed),
  role: String (tourist|transport|accommodation|guide),
  platform: String (web|mobile),
  isActive: Boolean (default: true),
  emailVerified: Boolean (default: false),
  avatar: String (optional),
  refreshTokens: [{
    token: String,
    createdAt: Date,
    expiresAt: Date
  }],
  createdAt: Date,
  updatedAt: Date
}
```

## Security Features

### Password Requirements
- Minimum 6 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one number

### Rate Limiting
- 5 attempts per 15 minutes per IP for auth endpoints

### JWT Configuration
- **Access Token**: 24 hours expiry
- **Refresh Token**: 7 days expiry
- Tokens include user ID, username, role, and platform

## Environment Variables

```bash
MONGO_URI="mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority"
JWT_SECRET="your-super-secret-jwt-key-change-this-in-production"
PORT=3001
```

## Installation & Usage

### Prerequisites
- Node.js 16+
- MongoDB Atlas or local MongoDB

### Setup
```bash
cd user-service
npm install
```

### Development
```bash
npm run dev     # With nodemon
# or
node index.js   # Direct execution
```

### Production
```bash
npm start
```

## Integration with Mobile App

The mobile app is configured to communicate with this service:

### API Configuration
```typescript
// services/config.ts
export const API_CONFIG = {
  BASE_URL: 'http://192.168.8.159:3001',
  ENDPOINTS: {
    AUTH: '/api/auth'
  }
}
```

### Authentication Flow
1. User selects role (`tourist` or `guide`) in signup form
2. Frontend sends role as `tourist`, backend maps to `traveller`  
3. JWT tokens are stored in AsyncStorage
4. Refresh token automatically renews access token
5. All authenticated requests include `Authorization: Bearer <token>`

## CORS Configuration

Configured to allow requests from:
- `http://localhost:5173` (Web app development)
- `http://192.168.8.159:8081` (Mobile app development)
- `exp://192.168.8.159:8081` (Expo development)

## Error Handling

All endpoints return consistent error responses:

### Validation Error
```json
{
  "success": false,
  "message": "Validation failed",
  "error": "Username must be at least 3 characters"
}
```

### Authentication Error  
```json
{
  "success": false,
  "message": "Invalid credentials",
  "error": "Invalid username/email or password"
}
```

### Server Error
```json
{
  "success": false,
  "message": "Internal server error",
  "error": "Registration failed. Please try again."
}
```

## Monitoring & Maintenance

### Logging
- Request logging with timestamps and user agents
- Error logging with stack traces
- MongoDB connection status logging

### Database Indexes
- Combined index on `username` and `email` for faster lookups
- Index on `refreshTokens` for token validation

### Token Cleanup
Use the cleanup endpoint to remove expired refresh tokens:
```bash
curl -X POST http://localhost:3001/api/auth/cleanup-tokens
```

## Future Enhancements

- [ ] Email verification implementation
- [ ] Password reset functionality  
- [ ] Account lockout after failed attempts
- [ ] OAuth integration (Google, Facebook)
- [ ] User profile management endpoints
- [ ] Audit logging for security events

## License

ISC License - WanderLanka Platform
