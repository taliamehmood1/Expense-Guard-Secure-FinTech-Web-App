💸 Expense Guard – Secure FinTech Web App
🎓 CY4053 – Secure FinTech App Development

Student: Talia Mehmood
Semester: BS FinTech – 7th Semester (Fall 2025)


🚀 Overview

Expense Guard is a Flask-based FinTech security application designed to showcase core cybersecurity principles — authentication, encryption, session management, validation, and audit logging — within a personal expense tracking system.

It combines secure coding practices with a modern, vibrant, and animated UI, ensuring both functionality and user appeal.

The app helps users securely manage, track, and analyze their expenses while maintaining data confidentiality and protection through encryption and robust input handling.

🧩 Key Features
🔐 1. Secure User Authentication

User registration and login using bcrypt password hashing

Strong password validation (uppercase, lowercase, digits, and symbols)

Prevents duplicate usernames and weak passwords

💰 2. Encrypted Expense Management

Add, delete, and view expenses

Data stored securely in SQLite with Fernet encryption

Automatic input validation and sanitization

🧠 3. AI-Style Dashboard Insights

Animated Chart.js graphs for monthly spending

Personalized spending messages (e.g., “You spent most on Food this month 🍕”)

🎨 4. Bright & Funky Theme

Modern color palette with vibrant gradients and smooth animations

Animate.css transitions and glowing hover effects

Visible logout button and clear navigation layout

👤 5. Profile Management

Update display name and email with validation

Optional profile picture upload (.jpg/.png only)

📜 6. Audit Logs & Activity Tracking

Logs user login, logout, and expense actions to audit_log.txt

Maintains a timestamp, username, and action trail for every event

🕒 7. Secure Session Handling

Auto logout after 5 minutes of inactivity

Prevents unauthorized dashboard access

⚙️ 8. Error Handling & Resilience

Friendly error messages — no stack traces

Custom animated 404 & 500 error pages

Unicode and emoji input fully supported (😊❤️💸)

🧪 Manual Cybersecurity Testing

A total of 20 manual security tests were performed to verify the app’s resilience against vulnerabilities.

Category	Examples
Input Validation	SQL injection, script tag rejection
Authentication & Session	Session expiry, lockout, unauthorized access
Error Handling	Safe error messages, divide-by-zero test
Data Security	Password hashing, data encryption
File Validation	Executable file rejection
Unicode Support	Emoji & special character input fix

📘 All test results and screenshots are documented in:
TaliaMehmood_Assignment2_TestCases.docx

🧰 Tech Stack
Component	Technology
Language	Python
Framework	Flask
Database	SQLite (encrypted with Fernet)
Frontend	HTML5, CSS3, Bootstrap 5, Animate.css, Chart.js
Libraries	flask, bcrypt, cryptography, sqlite3, datetime, re, os
📂 Project Structure
/ExpenseGuardApp
│
├── main.py
├── expense_guard.db
├── audit_log.txt
│
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── add_expense.html
│   ├── error.html
│
├── static/
│   ├── style.css
│   ├── animate.css (CDN linked)
│   ├── chart.js (CDN linked)
│
├── requirements.txt
└── README.md

⚡ Installation Guide
1️⃣ Clone the Repository
git clone https://github.com/yourusername/ExpenseGuardApp.git
cd ExpenseGuardApp

2️⃣ Install Dependencies
pip install -r requirements.txt

3️⃣ Run the Application
python main.py


🧠 Learning Outcomes

Practical understanding of secure web development in FinTech context

Implementation of encryption, validation, and logging mechanisms

Exposure to real-world cybersecurity testing (manual testing focus)

🏁 Status

✅ All 20 manual tests passed successfully.
✨ App stable, secure, and fully functional.


📧 Email: talia.mehmood@example.com
 (replace with yours)
💼 GitHub: github.com/yourusername
