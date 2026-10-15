# College Library Management System — Java

This is a separate Java web-app conversion of the Flask library system. The original Python folder and its files are unchanged. The SQLite database and static assets were copied into this project.

## Requirements

- Java 25 (latest LTS) or newer
- Maven 3.9 or newer

## Build and run

From this folder, build with the included Windows script (it uses the installed Java 25 and user-local Maven):

```powershell
.\build.bat
```

Then start the app with:

```powershell
.\run.bat
```

If Maven is on your `PATH`, you can instead build and run directly:

```powershell
mvn spring-boot:run
```

Open <http://localhost:8080>.

## Login

On first launch, open <http://localhost:8080/setup> on the same computer and create the main-admin username and a password of at least 14 characters. There is no built-in admin password. Setup is restricted to the local computer; the app listens only on `127.0.0.1`.

The app reads and writes `library.db` in this project folder. It does not point to the database in the Python project.

## Student portal

Students register at <http://localhost:8080/student/register> with the roll number and email on their library record and a one-time activation code issued by an admin from **Student Monitoring → View records**. The admin must share the code with that student through a verified institutional channel. Codes are single-use, expire after 48 hours, and are stored only as hashes. Students choose a password of at least 12 characters and sign in at <http://localhost:8080/student/login>. The librarian can also set/reset a student password in **View Members → Edit**.

Students cannot register a new library-member record themselves; their roll number/email must first be on file. Passwords are stored as BCrypt hashes. The app automatically adds the password-hash column to an existing Java-project database when it starts. Students can see their own profile, current and previous loans, due dates, overdue days and fines, and browse the searchable book catalog. Student accounts cannot access administrator pages.

## Main admin and sub-admins

After setting up the main admin, open **Admin Accounts → Add Sub-admin** to create another staff login. Sub-admins have the same library controls and can create other sub-admins. Admin creation is not public; an existing signed-in admin must create each account. Admin passwords must be at least 12 characters. The Admin Accounts page shows the role, creator, enabled status, and last sign-in, and supports resetting or disabling sub-admin accounts. The main-admin account is protected from being disabled there.

The authentication upgrade automatically locks existing admin accounts and requires the local first-time setup to choose a new main-admin username and password. After setup, sub-admin accounts remain disabled until the main admin explicitly re-enables or resets them.

## Authentication safeguards

- Spring Security CSRF protection covers all state-changing forms; logout uses POST.
- Login attempts are rate-limited to five failures per username and client address in 15 minutes, followed by a 15-minute block.
- Sessions expire after 20 minutes, use HttpOnly and SameSite=Lax cookies, and are rotated after sign-in.
- Student registration requires a short-lived, single-use invitation from a signed-in admin; knowing a roll number and email alone cannot claim an account.
- The app binds to localhost only. Do not expose it to a network without adding HTTPS, a properly configured trusted proxy, and a security review.

The dashboard and **Student Monitoring** page show account registration status, current loans, overdue counts, estimated fines, and each student's loan history. Each admin and student portal is role-restricted.

## Included features

- Dashboard and recent issue summary
- Book catalog search, category filtering, add, edit, and delete
- Member search, department filtering, registration, editing, and deletion
- Book checkout, return, and issued-record filters
- Three-book member limit, 15-day loan period, ₹45/day late fee, and overdue list
- Role-restricted student sign-in, personal loan/fine dashboard, and book catalog
- SQLite storage using the copied database
