# 🔐 Identity + JWT + Roles + QR Short-Lived Viewer

A **Full Stack ASP.NET Core Project** that integrates **Identity** with **JWT Authentication** to provide secure, flexible, and modern user management.  
It also includes a unique **QR-based short-lived viewer** feature that allows temporary guest access.

---

## 🚀 Features

### 🔑 Identity Integration
- User Registration & Login (ASP.NET Core Identity UI).
- Role-based authorization (Admin, User, Viewer).
- Custom UI for Register & Login pages (Bootstrap + responsive design).

### 🛡️ JWT Authentication
- Supports **short-lived JWT tokens**.
- Tokens can be generated alongside Identity cookies for APIs.
- Fine-grained access control based on roles.

### 👥 Role Management
- Create, view, and manage roles.
- Map users to specific roles.
- Admin dashboard for managing users & roles.

### 📱 QR Short-Lived Viewer (Special Feature)
- Generate a **QR Code** that contains a short-lived JWT with **Viewer role**.
- Any guest scanning the QR can access the **Viewer page** directly (no full account required).
- Perfect for demos, temporary access, or read-only dashboards.

### 🎨 UI/UX
- Modern **Bootstrap 5** + **Bootstrap Icons**.
- Responsive Navbar with:
  - Roles menu
  - QR generator (Admin only)
  - Dark/Light theme toggle
- Footer with branding & privacy link.

---




## ⚡ Tech Stack
- **ASP.NET Core  8**
- **Entity Framework Core**
- **SQL Server**
- **ASP.NET Core Identity**
- **JWT Bearer Authentication**
- **Bootstrap 5 + Icons**
- **QR Code Generator**

---

## 🔧 Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/YourUserName/Identity_JWT_Project.git
   cd Identity_JWT_Project
