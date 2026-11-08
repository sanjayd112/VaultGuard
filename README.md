VAULTGUARD
Secure File Storage and Intelligent Threat Protection System

Tagline: Secure Your Files. Protect Your Digital Identity.

1. Project Overview

VAULTGUARD is a secure file storage and intelligent threat protection web application developed using Python and Flask.

It provides secure file encryption, file integrity verification, version management, secure recovery and account risk monitoring.

2. Problem Statement

Traditional file storage systems can expose sensitive information to unauthorized access, data tampering and accidental data loss.

VAULTGUARD addresses these challenges through encryption, authentication, file integrity checking and secure recovery mechanisms.

3. Objectives
Protect confidential files through encryption.
Prevent unauthorized file access.
Detect file tampering.
Maintain file version history.
Provide secure file recovery.
Monitor suspicious account activities.
4. Technologies Used

Backend:

Python
Flask
Flask-SQLAlchemy
Flask-Login

Frontend:

HTML
CSS
Bootstrap 5
JavaScript
Chart.js

Database:

SQLite

Security:

AES-256-GCM
SHA-256
Argon2id
CSRF protection

5. Main Features
User registration and login.
Secure file upload.
AES-256-GCM file encryption.
Secure file download and decryption.
SHA-256 integrity verification.
File version management.
Secure file recovery.
Dynamic account risk assessment.
Security incident monitoring.
Administrator dashboard.

6. Project Structure
text
VaultGuard/
├── app.py
├── config.py
├── models.py
├── encryption.py
├── security.py
├── recovery.py
├── requirements.txt
├── README.md
├── LICENSE
├── .env.example
├── .gitignore
├── storage/
├── templates/
├── static/
└── tests/

7. Installation

Clone the repository:

bash
git clone https://github.com/YOUR_USERNAME/VaultGuard.git
cd VaultGuard


Create a virtual environment:

bash
python -m venv venv


Install the dependencies:

bash
pip install -r requirements.txt


Configure the required environment variables using .env.example. Generate and securely configure your own application secrets and encryption key.

8. Run the Application
bash
python app.py


Open the local application URL displayed in the terminal.

9. Run Automated Tests
bash
pytest -v

10. Security

VAULTGUARD uses authenticated encryption, password hashing, server-side access control and file integrity verification.

Encryption keys and application secrets must be configured securely and must never be committed to the public repository.

11. Demonstration

A project demonstration video is provided separately.

12. License

This project is licensed under the MIT License.

13. Academic Project

Developed as part of the GitHub Tool Project academic assignment.