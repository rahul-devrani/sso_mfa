# Single Sign-On (SSO) & Multi-Factor Authentication (MFA) System

## Project Overview
This project implements a secure authentication system using **Single Sign-On (SSO)** combined with **Multi-Factor Authentication (MFA)** and **Role-Based Access Control (RBAC)**.

It allows users to log in once and access multiple connected web applications securely without repeated authentication.

The system enhances security by combining:
- Password-based login
- Time-based One-Time Password (TOTP)
- JWT-based session management

---

## Features

- Single Sign-On (SSO)
- Multi-Factor Authentication (TOTP-based OTP)
- Role-Based Access Control (RBAC)
- Secure JWT Authentication (HttpOnly Cookies)
- Password Hashing & Security
- Multiple Client Apps Integration
- User Dashboard for MFA Management

---

## Project Architecture

The system is divided into two main components:

### Authentication Server
- Central security hub
- Handles:
  - User registration & login
  - MFA setup and verification
  - JWT token generation
  - Role assignment

### Client Applications
- Independent Flask apps (e.g., Notes App, Profile App)
- Trust the Authentication Server
- Use JWT token for:
  - Session validation
  - Role-based access control

---

## How It Works

1. **User Login**
   - User enters email & password
   - System verifies credentials

2. **MFA Verification**
   - User enters TOTP from authenticator app

3. **Token Generation**
   - Server generates JWT with:
     - User identity
     - Role (user/admin)

4. **Secure Storage**
   - JWT stored in HttpOnly cookie (`sso_token`)

5. **Accessing Client Apps**
   - Client app reads token
   - Verifies authenticity
   - Applies RBAC rules

---

## Tech Stack

- **Backend:** Python (Flask)  
- **Database:** SQLite  
- **Frontend:** HTML, CSS  

### Security Libraries
- `PyJWT` → JWT creation & validation  
- `pyotp` → TOTP (MFA) generation  
- `Werkzeug` → Password hashing  

---

## Security Concepts Used

- JWT (JSON Web Tokens)
- Multi-Factor Authentication (TOTP)
- Role-Based Access Control (RBAC)
- Secure Cookies (HttpOnly)
- Password Hashing
- Session Management

---

## Project Deliverables

- Authentication Server (Flask-based)
- MFA-enabled login system (OTP verification)
- SSO implementation across multiple apps
- RBAC-enabled client applications
- Secure JWT-based session handling
- SQLite database with hashed passwords
- Simple frontend (HTML/CSS)

---

## System Components

### Authentication Server
- Handles login, MFA, token generation

### Client Apps
- Validate JWT token
- Enforce role-based access

### Database (SQLite)
Stores:
- User credentials
- Roles
- MFA secrets

---

## Role-Based Access Control (RBAC)

- Roles assigned by Auth Server:
  - `user`
  - `admin`

- Client apps enforce:
  - Admin-only dashboards
  - Restricted routes

---

## How to Run the Project

```bash
# Clone the repository

# Navigate to folder

# Install dependencies
pip install flask pyjwt pyotp

# Run Authentication Server
python auth_server.py

# Run Client Apps (in separate terminals)
python app1.py
python app2.py
