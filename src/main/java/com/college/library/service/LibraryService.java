package com.college.library.service;

import jakarta.annotation.PostConstruct;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

@Service
public class LibraryService {
    public static final List<String> BOOK_CATEGORIES = List.of(
            "Computer Science", "Mathematics", "Physics", "Chemistry", "Biology", "Electronics",
            "Mechanical Engineering", "Civil Engineering", "Literature", "History", "Economics",
            "Management", "Law", "Other");

    public static final List<String> DEPARTMENTS = List.of(
            "Computer Science & Engineering", "Information Technology", "Electronics & Communication",
            "Mechanical Engineering", "Civil Engineering", "Electrical Engineering", "Physics",
            "Chemistry", "Mathematics", "Management", "Other");

    private static final DateTimeFormatter DATABASE_DATE_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final long LOGIN_WINDOW_MILLIS = Duration.ofMinutes(15).toMillis();
    private static final long LOGIN_BLOCK_MILLIS = Duration.ofMinutes(15).toMillis();
    private static final int MAX_LOGIN_FAILURES = 5;
    private static final long INVITE_LIFETIME_MILLIS = Duration.ofHours(48).toMillis();

    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwordEncoder;

    public LibraryService(JdbcTemplate jdbc, PasswordEncoder passwordEncoder) {
        this.jdbc = jdbc;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initializeDatabase() {
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS books (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    author TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'Other',
                    quantity INTEGER NOT NULL DEFAULT 0
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS members (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    roll_number TEXT UNIQUE NOT NULL,
                    department TEXT NOT NULL,
                    email TEXT,
                    phone TEXT,
                    address TEXT,
                    join_date TEXT NOT NULL,
                    password_hash TEXT
                )
                """);
        boolean passwordColumnExists = jdbc.queryForList("PRAGMA table_info(members)").stream()
                .anyMatch(column -> "password_hash".equals(column.get("name")));
        if (!passwordColumnExists) {
            jdbc.execute("ALTER TABLE members ADD COLUMN password_hash TEXT");
        }
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS issued_books (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    book_id TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    issued_date TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    return_date TEXT,
                    number_of_days INTEGER,
                    fine INTEGER DEFAULT 0,
                    FOREIGN KEY (book_id) REFERENCES books(id),
                    FOREIGN KEY (member_id) REFERENCES members(id)
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS admin_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('MAIN','SUB')),
                    created_by INTEGER,
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY (created_by) REFERENCES admin_accounts(id)
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS auth_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS auth_login_attempts (
                    attempt_key TEXT PRIMARY KEY,
                    failures INTEGER NOT NULL,
                    window_started INTEGER NOT NULL,
                    blocked_until INTEGER NOT NULL DEFAULT 0
                )
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS student_activation_tokens (
                    token_hash TEXT PRIMARY KEY,
                    member_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    issued_by INTEGER NOT NULL,
                    FOREIGN KEY (member_id) REFERENCES members(id),
                    FOREIGN KEY (issued_by) REFERENCES admin_accounts(id)
                )
                """);
        if (count("SELECT COUNT(*) FROM auth_settings WHERE setting_key='bootstrap_complete'") == 0) {
            jdbc.update("UPDATE admin_accounts SET enabled=0");
            jdbc.update("INSERT INTO auth_settings (setting_key,setting_value) VALUES ('bootstrap_complete','false')");
        }
        seedData();
    }

    public boolean isBootstrapComplete() {
        return count("SELECT COUNT(*) FROM auth_settings WHERE setting_key='bootstrap_complete' AND setting_value='true'") == 1;
    }

    @Transactional
    public OperationResult completeInitialSetup(String username, String password) {
        String normalizedUsername = username.trim();
        if (isBootstrapComplete()) {
            return OperationResult.failure("Initial setup has already been completed.");
        }
        if (!normalizedUsername.matches("[A-Za-z0-9._-]{3,32}")) {
            return OperationResult.failure("Use 3–32 letters, numbers, dots, underscores, or hyphens for the username.");
        }
        if (password.length() < 14) {
            return OperationResult.failure("Choose a main-admin password with at least 14 characters.");
        }
        List<Map<String, Object>> mainAccounts = jdbc.queryForList(
                "SELECT id FROM admin_accounts WHERE role='MAIN' ORDER BY id LIMIT 1");
        if (!mainAccounts.isEmpty()) {
            long mainId = ((Number) mainAccounts.getFirst().get("id")).longValue();
            if (count("SELECT COUNT(*) FROM admin_accounts WHERE username=? COLLATE NOCASE AND id<>?",
                    normalizedUsername, mainId) > 0) {
                return OperationResult.failure("That username is already in use.");
            }
            jdbc.update("""
                    UPDATE admin_accounts SET username=?,password_hash=?,enabled=1,last_login=NULL
                    WHERE id=? AND role='MAIN'
                    """, normalizedUsername, passwordEncoder.encode(password), mainId);
        } else {
            if (count("SELECT COUNT(*) FROM admin_accounts WHERE username=? COLLATE NOCASE",
                    normalizedUsername) > 0) {
                return OperationResult.failure("That username is already in use.");
            }
            jdbc.update("""
                    INSERT INTO admin_accounts
                    (username,password_hash,role,created_at,enabled)
                    VALUES (?,?, 'MAIN', ?,1)
                    """, normalizedUsername, passwordEncoder.encode(password),
                    LocalDateTime.now().format(DATABASE_DATE_TIME));
        }
        jdbc.update("UPDATE admin_accounts SET enabled=0 WHERE role='SUB'");
        jdbc.update("UPDATE auth_settings SET setting_value='true' WHERE setting_key='bootstrap_complete'");
        return OperationResult.success("Main admin created. Sign in with the credentials you just set.");
    }

    private void seedData() {
        if (jdbc.queryForObject("SELECT COUNT(*) FROM books", Integer.class) > 0) {
            return;
        }
        Object[][] books = {
                {"B001", "Introduction to Algorithms", "Cormen et al.", "Computer Science", 5},
                {"B002", "Computer Networks", "Andrew Tanenbaum", "Computer Science", 3},
                {"B003", "Database System Concepts", "Silberschatz", "Computer Science", 4},
                {"B004", "Engineering Mathematics", "B.S. Grewal", "Mathematics", 6},
                {"B005", "Engineering Physics", "S.K. Gupta", "Physics", 3},
                {"B006", "Signals and Systems", "Oppenheim", "Electronics", 2},
                {"B007", "Strength of Materials", "R.K. Bansal", "Mechanical Engineering", 4},
                {"B008", "Fluid Mechanics", "Frank White", "Mechanical Engineering", 2},
                {"B009", "Organic Chemistry", "Morrison Boyd", "Chemistry", 3},
                {"B010", "Data Structures", "Mark Allen Weiss", "Computer Science", 5},
                {"B011", "Operating Systems", "Galvin", "Computer Science", 3},
                {"B012", "Discrete Mathematics", "Kenneth Rosen", "Mathematics", 4},
                {"B013", "Principles of Economics", "N. G. Mankiw", "Economics", 2},
                {"B014", "Business Management", "P. C. Tripathi", "Management", 3},
                {"B015", "Electrical Technology", "B.L. Theraja", "Electronics", 2}
        };
        for (Object[] book : books) {
            jdbc.update("INSERT INTO books (id,title,author,category,quantity) VALUES (?,?,?,?,?)", book);
        }

        Object[][] members = {
                {"M001", "Alice Smith", "CS2021001", "Computer Science & Engineering", "alice@college.edu", "9876543210", "123 Main St", "2021-07-15"},
                {"M002", "Bob Johnson", "IT2021002", "Information Technology", "bob@college.edu", "9876543211", "234 Elm St", "2021-07-15"},
                {"M003", "Charlie Brown", "ME2022003", "Mechanical Engineering", "charlie@college.edu", "9876543212", "345 Oak St", "2022-07-20"},
                {"M004", "David Wilson", "CE2022004", "Civil Engineering", "david@college.edu", "9876543213", "456 Pine St", "2022-07-20"},
                {"M005", "Eva Green", "CS2023005", "Computer Science & Engineering", "eva@college.edu", "9876543214", "567 Maple St", "2023-07-18"}
        };
        for (Object[] member : members) {
            jdbc.update("""
                    INSERT INTO members
                    (id,name,roll_number,department,email,phone,address,join_date)
                    VALUES (?,?,?,?,?,?,?,?)
                    """, member);
        }
    }

    public Map<String, Object> dashboard() {
        Map<String, Object> summary = Map.of(
                "totalBooks", number("SELECT COALESCE(SUM(quantity),0) FROM books"),
                "totalTitles", number("SELECT COUNT(*) FROM books"),
                "totalMembers", number("SELECT COUNT(*) FROM members"),
                "activeIssues", number("SELECT COUNT(*) FROM issued_books WHERE return_date IS NULL"),
                "overdueCount", number("""
                        SELECT COUNT(*) FROM issued_books
                        WHERE return_date IS NULL AND due_date < datetime('now','localtime')
                        """),
                "totalFines", number("SELECT COALESCE(SUM(fine),0) FROM issued_books"));
        return summary;
    }

    public Map<String, Object> monitoringSummary() {
        return Map.of(
                "totalAdmins", number("SELECT COUNT(*) FROM admin_accounts WHERE enabled=1"),
                "totalStudentAccounts", number("SELECT COUNT(*) FROM members WHERE password_hash IS NOT NULL"),
                "unregisteredStudents", number("SELECT COUNT(*) FROM members WHERE password_hash IS NULL"),
                "studentActiveLoans", number("""
                        SELECT COUNT(*) FROM issued_books ib JOIN members m ON m.id=ib.member_id
                        WHERE ib.return_date IS NULL AND m.password_hash IS NOT NULL
                        """),
                "studentOverdueLoans", number("""
                        SELECT COUNT(*) FROM issued_books ib JOIN members m ON m.id=ib.member_id
                        WHERE ib.return_date IS NULL AND ib.due_date < datetime('now','localtime')
                          AND m.password_hash IS NOT NULL
                        """));
    }

    public List<Map<String, Object>> adminAccounts() {
        return jdbc.queryForList("""
                SELECT a.id,a.username,a.role,a.enabled,a.created_at,a.last_login,
                       creator.username AS created_by,
                       (SELECT COUNT(*) FROM admin_accounts child WHERE child.created_by=a.id) AS admins_created
                FROM admin_accounts a
                LEFT JOIN admin_accounts creator ON creator.id=a.created_by
                ORDER BY CASE a.role WHEN 'MAIN' THEN 0 ELSE 1 END,a.username COLLATE NOCASE
                """);
    }

    public List<Map<String, Object>> recentAdminLogins() {
        return jdbc.queryForList("""
                SELECT username,role,last_login FROM admin_accounts
                WHERE enabled=1 ORDER BY last_login DESC,username COLLATE NOCASE LIMIT 8
                """);
    }

    public Map<String, Object> authenticateAdmin(String username, String password) {
        List<Map<String, Object>> matches = jdbc.queryForList("""
                SELECT id,username,password_hash,role FROM admin_accounts
                WHERE username=? COLLATE NOCASE AND enabled=1
                """, username.trim());
        if (matches.isEmpty()) {
            return null;
        }
        Map<String, Object> account = matches.getFirst();
        if (!passwordEncoder.matches(password, (String) account.get("password_hash"))) {
            return null;
        }
        jdbc.update("UPDATE admin_accounts SET last_login=? WHERE id=?",
                LocalDateTime.now().format(DATABASE_DATE_TIME), account.get("id"));
        return account;
    }

    public boolean loginBlocked(String role, String username, String remoteAddress) {
        long now = System.currentTimeMillis();
        String key = loginAttemptKey(role, username, remoteAddress);
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT blocked_until FROM auth_login_attempts WHERE attempt_key=?", key);
        return !rows.isEmpty() && ((Number) rows.getFirst().get("blocked_until")).longValue() > now;
    }

    public void recordFailedLogin(String role, String username, String remoteAddress) {
        long now = System.currentTimeMillis();
        long windowStart = now - LOGIN_WINDOW_MILLIS;
        long blockedUntil = now + LOGIN_BLOCK_MILLIS;
        String key = loginAttemptKey(role, username, remoteAddress);
        jdbc.update("""
                INSERT INTO auth_login_attempts (attempt_key,failures,window_started,blocked_until)
                VALUES (?,1,?,0)
                ON CONFLICT(attempt_key) DO UPDATE SET
                    failures=CASE WHEN auth_login_attempts.window_started < ? THEN 1
                                  ELSE auth_login_attempts.failures+1 END,
                    window_started=CASE WHEN auth_login_attempts.window_started < ? THEN ?
                                        ELSE auth_login_attempts.window_started END,
                    blocked_until=CASE WHEN auth_login_attempts.window_started < ? THEN 0
                                       WHEN auth_login_attempts.failures+1 >= ? THEN ?
                                       ELSE auth_login_attempts.blocked_until END
                """, key, now, windowStart, windowStart, now, windowStart, MAX_LOGIN_FAILURES, blockedUntil);
    }

    public void clearLoginFailures(String role, String username, String remoteAddress) {
        jdbc.update("DELETE FROM auth_login_attempts WHERE attempt_key=?",
                loginAttemptKey(role, username, remoteAddress));
    }

    private String loginAttemptKey(String role, String username, String remoteAddress) {
        String source = role + "\n" + username.trim().toLowerCase(java.util.Locale.ROOT)
                + "\n" + remoteAddress;
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(source.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime.", exception);
        }
    }

    public boolean isAdminEnabled(long adminId) {
        return count("SELECT COUNT(*) FROM admin_accounts WHERE id=? AND enabled=1", adminId) == 1;
    }

    @Transactional
    public OperationResult createSubAdmin(String username, String password, long creatorId) {
        String normalizedUsername = username.trim();
        if (!normalizedUsername.matches("[A-Za-z0-9._-]{3,32}")) {
            return OperationResult.failure("Use 3–32 letters, numbers, dots, underscores, or hyphens for the username.");
        }
        if (password.length() < 12) {
            return OperationResult.failure("Admin passwords must be at least 12 characters.");
        }
        if (count("SELECT COUNT(*) FROM admin_accounts WHERE username=? COLLATE NOCASE",
                normalizedUsername) > 0) {
            return OperationResult.failure("That admin username is already in use.");
        }
        jdbc.update("""
                INSERT INTO admin_accounts
                (username,password_hash,role,created_by,created_at,enabled)
                VALUES (?,?,?,?,?,1)
                """, normalizedUsername, passwordEncoder.encode(password), "SUB", creatorId,
                LocalDateTime.now().format(DATABASE_DATE_TIME));
        return OperationResult.success("Sub-admin account \"" + normalizedUsername + "\" created.");
    }

    @Transactional
    public OperationResult resetAdminPassword(long adminId, String password) {
        if (password.length() < 12) {
            return OperationResult.failure("Admin passwords must be at least 12 characters.");
        }
        Map<String, Object> target = one("SELECT id,username,role FROM admin_accounts WHERE id=?", adminId);
        if (target == null) {
            return OperationResult.failure("Admin account not found.");
        }
        if ("MAIN".equals(target.get("role"))) {
            return OperationResult.failure("The main admin account cannot be changed here.");
        }
        jdbc.update("UPDATE admin_accounts SET password_hash=? WHERE id=?",
                passwordEncoder.encode(password), adminId);
        return OperationResult.success("Password reset for sub-admin \"" + target.get("username") + "\".");
    }

    @Transactional
    public OperationResult setAdminEnabled(long adminId, boolean enabled, long currentAdminId) {
        Map<String, Object> target = one("SELECT id,username,role FROM admin_accounts WHERE id=?", adminId);
        if (target == null) {
            return OperationResult.failure("Admin account not found.");
        }
        if ("MAIN".equals(target.get("role"))) {
            return OperationResult.failure("The main admin account cannot be disabled.");
        }
        if (adminId == currentAdminId && !enabled) {
            return OperationResult.failure("You cannot disable your own admin account.");
        }
        jdbc.update("UPDATE admin_accounts SET enabled=? WHERE id=?", enabled ? 1 : 0, adminId);
        return OperationResult.success("Sub-admin \"" + target.get("username") + "\" "
                + (enabled ? "enabled." : "disabled."));
    }

    public List<Map<String, Object>> monitoredStudents(String query) {
        return jdbc.queryForList("""
                SELECT m.id,m.name,m.roll_number,m.department,m.email,m.phone,m.join_date,
                       CASE WHEN m.password_hash IS NULL THEN 0 ELSE 1 END AS registered,
                       (SELECT COUNT(*) FROM issued_books ib
                        WHERE ib.member_id=m.id AND ib.return_date IS NULL) AS active_loans,
                       (SELECT COALESCE(SUM(CASE WHEN ib.return_date IS NULL
                                           THEN MAX(0,CAST(julianday('now','localtime')-julianday(ib.due_date) AS INTEGER))*45
                                           ELSE ib.fine END),0)
                        FROM issued_books ib WHERE ib.member_id=m.id) AS fines
                FROM members m
                WHERE m.name LIKE ? OR m.roll_number LIKE ? OR COALESCE(m.email,'') LIKE ?
                ORDER BY m.name COLLATE NOCASE
                """, "%" + query + "%", "%" + query + "%", "%" + query + "%");
    }

    @Transactional
    public Map<String, Object> registerStudent(String rollNumber, String email, String activationCode,
                                               String password) {
        if (password.length() < 12) {
            return Map.of("success", false,
                    "message", "Choose a password with at least 12 characters.");
        }
        String tokenHash = sha256(activationCode.trim());
        long now = System.currentTimeMillis();
        List<Map<String, Object>> matches = jdbc.queryForList("""
                SELECT m.id,m.password_hash FROM members m
                JOIN student_activation_tokens t ON t.member_id=m.id
                WHERE m.roll_number=? COLLATE NOCASE AND m.email IS NOT NULL AND trim(m.email)<>''
                  AND lower(trim(m.email))=lower(trim(?))
                  AND t.token_hash=? AND t.used=0 AND t.expires_at>?
                """, rollNumber.trim(), email.trim(), tokenHash, now);
        if (matches.isEmpty()) {
            return Map.of("success", false,
                    "message", "The roll number, registered email, and valid invitation code could not be verified. Contact the librarian for a new code.");
        }
        Map<String, Object> member = matches.getFirst();
        if (member.get("password_hash") != null) {
            return Map.of("success", false,
                    "message", "A portal account already exists for that roll number. Sign in or ask the librarian to reset your password.");
        }
        int updated = jdbc.update("UPDATE members SET password_hash=? WHERE id=? AND password_hash IS NULL",
                passwordEncoder.encode(password), member.get("id"));
        if (updated != 1) {
            return Map.of("success", false,
                    "message", "A student portal account was just created for that roll number. Please sign in.");
        }
        int consumed = jdbc.update("""
                UPDATE student_activation_tokens SET used=1
                WHERE token_hash=? AND member_id=? AND used=0 AND expires_at>?
                """, tokenHash, member.get("id"), now);
        if (consumed != 1) {
            throw new IllegalStateException("Student activation code could not be consumed atomically.");
        }
        return Map.of("success", true, "message", "Student portal account created. You can now sign in.");
    }

    @Transactional
    public StudentActivationResult createStudentActivationCode(String memberId, long adminId) {
        Map<String, Object> member = member(memberId);
        if (member == null) {
            return new StudentActivationResult(OperationResult.failure("Student record not found."), null);
        }
        if (member.get("email") == null || member.get("email").toString().isBlank()) {
            return new StudentActivationResult(
                    OperationResult.failure("Add a registered email address to the student record first."), null);
        }
        if (member.get("account_enabled") != null
                && ((Number) member.get("account_enabled")).intValue() == 1) {
            return new StudentActivationResult(OperationResult.failure("This student already has a portal account."), null);
        }
        byte[] tokenBytes = new byte[32];
        SECURE_RANDOM.nextBytes(tokenBytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        String tokenHash = sha256(code);
        jdbc.update("UPDATE student_activation_tokens SET used=1 WHERE member_id=? AND used=0", memberId);
        jdbc.update("""
                INSERT INTO student_activation_tokens(token_hash,member_id,expires_at,issued_by)
                VALUES (?,?,?,?)
                """, tokenHash, memberId, System.currentTimeMillis() + INVITE_LIFETIME_MILLIS, adminId);
        return new StudentActivationResult(
                OperationResult.success("One-time student invitation created. Share it with the student through a verified channel; it expires in 48 hours."),
                code);
    }

    private String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime.", exception);
        }
    }

    public List<Map<String, Object>> recentIssues() {
        return jdbc.queryForList("""
                SELECT ib.id,b.title,m.name,m.roll_number,ib.issued_date,ib.due_date
                FROM issued_books ib JOIN books b ON ib.book_id=b.id
                JOIN members m ON ib.member_id=m.id
                WHERE ib.return_date IS NULL ORDER BY ib.issued_date DESC LIMIT 5
                """);
    }

    public List<Map<String, Object>> books(String query, String category) {
        StringBuilder sql = new StringBuilder("SELECT * FROM books WHERE 1=1");
        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        if (!query.isBlank()) {
            sql.append(" AND (title LIKE ? OR author LIKE ? OR id LIKE ?)");
            String like = "%" + query + "%";
            args.add(like);
            args.add(like);
            args.add(like);
        }
        if (!category.isBlank()) {
            sql.append(" AND category=?");
            args.add(category);
        }
        sql.append(" ORDER BY title");
        return jdbc.queryForList(sql.toString(), args.toArray());
    }

    public Map<String, Object> book(String id) {
        return one("SELECT * FROM books WHERE id=?", id);
    }

    @Transactional
    public OperationResult saveBook(String id, String title, String author, String category, int quantity) {
        if (id == null) {
            List<Map<String, Object>> existing = jdbc.queryForList(
                    "SELECT id FROM books WHERE title=? AND author=?", title, author);
            if (!existing.isEmpty()) {
                jdbc.update("UPDATE books SET quantity=quantity+? WHERE id=?", quantity, existing.getFirst().get("id"));
                return OperationResult.success("Updated quantity for \"" + title + "\". Added " + quantity + " more copies.");
            }
            jdbc.update("INSERT INTO books (id,title,author,category,quantity) VALUES (?,?,?,?,?)",
                    nextId("B", "books"), title, author, category, quantity);
            return OperationResult.success("Book \"" + title + "\" added successfully!");
        }
        int changed = jdbc.update("UPDATE books SET title=?,author=?,category=?,quantity=? WHERE id=?",
                title, author, category, quantity, id);
        return changed == 0
                ? OperationResult.failure("Book not found.")
                : OperationResult.success("Book \"" + title + "\" updated successfully!");
    }

    @Transactional
    public OperationResult deleteBook(String id) {
        if (count("SELECT COUNT(*) FROM issued_books WHERE book_id=? AND return_date IS NULL", id) > 0) {
            return OperationResult.failure("Cannot delete: this book is currently issued to a member.");
        }
        Map<String, Object> book = book(id);
        if (book == null) {
            return OperationResult.failure("Book not found.");
        }
        jdbc.update("DELETE FROM books WHERE id=?", id);
        return OperationResult.success("Book \"" + book.get("title") + "\" deleted.");
    }

    public List<Map<String, Object>> members(String query, String department) {
        StringBuilder sql = new StringBuilder("""
                SELECT id,name,roll_number,department,email,phone,address,join_date,
                       CASE WHEN password_hash IS NULL THEN 0 ELSE 1 END AS account_enabled
                FROM members WHERE 1=1
                """);
        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        if (!query.isBlank()) {
            sql.append(" AND (name LIKE ? OR roll_number LIKE ? OR email LIKE ?)");
            String like = "%" + query + "%";
            args.add(like);
            args.add(like);
            args.add(like);
        }
        if (!department.isBlank()) {
            sql.append(" AND department=?");
            args.add(department);
        }
        sql.append(" ORDER BY name");
        return jdbc.queryForList(sql.toString(), args.toArray());
    }

    public Map<String, Object> member(String id) {
        return one("""
                SELECT id,name,roll_number,department,email,phone,address,join_date,
                       CASE WHEN password_hash IS NULL THEN 0 ELSE 1 END AS account_enabled
                FROM members WHERE id=?
                """, id);
    }

    public Map<String, Integer> activeIssueCounts() {
        Map<String, Integer> counts = new java.util.HashMap<>();
        jdbc.queryForList("""
                SELECT member_id,COUNT(*) AS cnt FROM issued_books
                WHERE return_date IS NULL GROUP BY member_id
                """).forEach(row -> counts.put((String) row.get("member_id"), ((Number) row.get("cnt")).intValue()));
        return counts;
    }

    @Transactional
    public OperationResult saveMember(String id, String name, String rollNumber, String department,
                                      String email, String phone, String address, String password) {
        rollNumber = rollNumber.trim().toUpperCase();
        if (id == null) {
            if (count("SELECT COUNT(*) FROM members WHERE roll_number=?", rollNumber) > 0) {
                return OperationResult.failure("A member with roll number " + rollNumber + " already exists.");
            }
            if (password.isBlank()) {
                jdbc.update("""
                        INSERT INTO members
                        (id,name,roll_number,department,email,phone,address,join_date)
                        VALUES (?,?,?,?,?,?,?,?)
                        """, nextId("M", "members"), name, rollNumber, department, email, phone, address,
                        LocalDate.now().toString());
            } else {
                jdbc.update("""
                        INSERT INTO members
                        (id,name,roll_number,department,email,phone,address,join_date,password_hash)
                        VALUES (?,?,?,?,?,?,?,?,?)
                        """, nextId("M", "members"), name, rollNumber, department, email, phone, address,
                        LocalDate.now().toString(), passwordEncoder.encode(password));
            }
            return OperationResult.success("Member \"" + name + "\" (Roll: " + rollNumber + ") registered successfully!");
        }
        if (count("SELECT COUNT(*) FROM members WHERE roll_number=? AND id<>?", rollNumber, id) > 0) {
            return OperationResult.failure("Roll number " + rollNumber + " is already taken by another member.");
        }
        int changed;
        if (password.isBlank()) {
            changed = jdbc.update("""
                    UPDATE members SET name=?,roll_number=?,department=?,email=?,phone=?,address=? WHERE id=?
                    """, name, rollNumber, department, email, phone, address, id);
        } else {
            changed = jdbc.update("""
                    UPDATE members SET name=?,roll_number=?,department=?,email=?,phone=?,address=?,password_hash=?
                    WHERE id=?
                    """, name, rollNumber, department, email, phone, address, passwordEncoder.encode(password), id);
        }
        return changed == 0
                ? OperationResult.failure("Member not found.")
                : OperationResult.success("Member \"" + name + "\" updated successfully!");
    }

    @Transactional
    public OperationResult deleteMember(String id) {
        if (count("SELECT COUNT(*) FROM issued_books WHERE member_id=? AND return_date IS NULL", id) > 0) {
            return OperationResult.failure("Cannot delete: member currently has books issued.");
        }
        Map<String, Object> member = member(id);
        if (member == null) {
            return OperationResult.failure("Member not found.");
        }
        jdbc.update("DELETE FROM members WHERE id=?", id);
        return OperationResult.success("Member \"" + member.get("name") + "\" deleted.");
    }

    public List<Map<String, Object>> availableBooks() {
        return jdbc.queryForList("SELECT * FROM books WHERE quantity>0 ORDER BY title");
    }

    public List<Map<String, Object>> allMembers() {
        return jdbc.queryForList("SELECT id,name,roll_number,department FROM members ORDER BY name");
    }

    public Map<String, Object> authenticateStudent(String rollNumber, String password) {
        List<Map<String, Object>> accounts = jdbc.queryForList(
                "SELECT id,password_hash FROM members WHERE roll_number=?", rollNumber.trim().toUpperCase());
        if (accounts.isEmpty()) {
            return null;
        }
        Map<String, Object> account = accounts.getFirst();
        String passwordHash = (String) account.get("password_hash");
        if (passwordHash == null || !passwordEncoder.matches(password, passwordHash)) {
            return null;
        }
        return member((String) account.get("id"));
    }

    public Map<String, Object> studentSummary(String memberId) {
        List<Map<String, Object>> loans = studentLoans(memberId);
        long active = 0;
        long returned = 0;
        long overdue = 0;
        long fines = 0;
        for (Map<String, Object> loan : loans) {
            if (loan.get("return_date") == null) {
                active++;
                if (((Number) loan.get("days_overdue")).longValue() > 0) {
                    overdue++;
                }
            } else {
                returned++;
            }
            fines += ((Number) loan.get("estimated_fine")).longValue();
        }
        return Map.of("activeLoans", active, "returnedLoans", returned,
                "overdueLoans", overdue, "totalFines", fines);
    }

    public List<Map<String, Object>> studentLoans(String memberId) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT ib.id,b.title,b.author,b.category,
                       ib.issued_date,ib.due_date,ib.return_date,ib.number_of_days,ib.fine,
                       CASE WHEN ib.return_date IS NULL AND ib.due_date < datetime('now','localtime')
                            THEN MAX(0,CAST(julianday('now','localtime')-julianday(ib.due_date) AS INTEGER))
                            ELSE 0 END AS days_overdue,
                       CASE WHEN ib.return_date IS NULL
                            THEN MAX(ib.fine,MAX(0,CAST(julianday('now','localtime')-julianday(ib.due_date) AS INTEGER))*45)
                            ELSE ib.fine END AS estimated_fine
                FROM issued_books ib JOIN books b ON ib.book_id=b.id
                WHERE ib.member_id=? ORDER BY ib.issued_date DESC
                """, memberId);
        return rows;
    }

    @Transactional
    public OperationResult issueBook(String bookId, String memberId, LocalDateTime issuedAt) {
        Map<String, Object> book = book(bookId);
        Map<String, Object> member = member(memberId);
        if (book == null || member == null) {
            return OperationResult.failure("Invalid book or member selected.");
        }
        if (((Number) book.get("quantity")).intValue() <= 0) {
            return OperationResult.failure("\"" + book.get("title") + "\" is currently out of stock.");
        }
        if (count("SELECT COUNT(*) FROM issued_books WHERE member_id=? AND return_date IS NULL", memberId) >= 3) {
            return OperationResult.failure(member.get("name") + " already has 3 books issued. Return a book first.");
        }
        if (count("""
                SELECT COUNT(*) FROM issued_books
                WHERE book_id=? AND member_id=? AND return_date IS NULL
                """, bookId, memberId) > 0) {
            return OperationResult.failure(member.get("name") + " already has \"" + book.get("title") + "\" issued.");
        }
        LocalDateTime dueAt = issuedAt.plusDays(15);
        jdbc.update("""
                INSERT INTO issued_books (book_id,member_id,issued_date,due_date,fine)
                VALUES (?,?,?,?,0)
                """, bookId, memberId, format(issuedAt), format(dueAt));
        jdbc.update("UPDATE books SET quantity=quantity-1 WHERE id=?", bookId);
        return OperationResult.success("\"" + book.get("title") + "\" issued to " + member.get("name")
                + ". Due: " + dueAt.format(DateTimeFormatter.ofPattern("dd MMM yyyy")) + ".");
    }

    public List<Map<String, Object>> issuedBooks(String status, String query) {
        StringBuilder sql = new StringBuilder("""
                SELECT ib.id,b.id AS book_id,b.title,b.category,
                       m.id AS member_id,m.name AS member_name,m.roll_number,
                       ib.issued_date,ib.due_date,ib.return_date,ib.number_of_days,ib.fine
                FROM issued_books ib JOIN books b ON ib.book_id=b.id
                JOIN members m ON ib.member_id=m.id WHERE 1=1
                """);
        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        switch (status) {
            case "active" -> sql.append(" AND ib.return_date IS NULL");
            case "returned" -> sql.append(" AND ib.return_date IS NOT NULL");
            case "overdue" -> {
                sql.append(" AND ib.return_date IS NULL AND ib.due_date < datetime('now','localtime')");
            }
            default -> { }
        }
        if (!query.isBlank()) {
            sql.append(" AND (b.title LIKE ? OR m.name LIKE ? OR m.roll_number LIKE ?)");
            String like = "%" + query + "%";
            args.add(like);
            args.add(like);
            args.add(like);
        }
        sql.append(" ORDER BY ib.issued_date DESC");
        return jdbc.queryForList(sql.toString(), args.toArray());
    }

    public List<Map<String, Object>> activeIssues() {
        return jdbc.queryForList("""
                SELECT ib.id,b.title,m.name,m.roll_number,ib.issued_date,ib.due_date
                FROM issued_books ib JOIN books b ON ib.book_id=b.id
                JOIN members m ON ib.member_id=m.id
                WHERE ib.return_date IS NULL ORDER BY ib.due_date
                """);
    }

    @Transactional
    public OperationResult returnBook(long issueId, LocalDateTime returnedAt) {
        List<Map<String, Object>> issues = jdbc.queryForList("SELECT * FROM issued_books WHERE id=?", issueId);
        if (issues.isEmpty()) {
            return OperationResult.failure("No matching issued record found.");
        }
        Map<String, Object> issue = issues.getFirst();
        if (issue.get("return_date") != null) {
            return OperationResult.failure("This book has already been returned.");
        }
        LocalDateTime issuedAt = LocalDateTime.parse((String) issue.get("issued_date"), DATABASE_DATE_TIME);
        long days = Duration.between(issuedAt, returnedAt).toDays();
        int fine = (int) Math.max(0, (days - 15) * 45);
        jdbc.update("""
                UPDATE issued_books SET return_date=?,number_of_days=?,fine=? WHERE id=?
                """, format(returnedAt), days, fine, issueId);
        jdbc.update("UPDATE books SET quantity=quantity+1 WHERE id=?", issue.get("book_id"));
        String title = (String) jdbc.queryForObject("SELECT title FROM books WHERE id=?",
                String.class, issue.get("book_id"));
        String message = fine > 0
                ? "\"" + title + "\" returned. Fine: ₹" + fine + " (" + days + " days)."
                : "\"" + title + "\" returned on time. No fine.";
        return fine > 0 ? OperationResult.warning(message) : OperationResult.success(message);
    }

    public List<Map<String, Object>> overdueBooks() {
        return jdbc.queryForList("""
                SELECT ib.id,b.title,b.category,m.name AS member_name,m.roll_number,
                       m.department,m.phone,ib.issued_date,ib.due_date,
                       CAST((julianday('now','localtime')-julianday(ib.due_date)) AS INTEGER) AS days_overdue
                FROM issued_books ib JOIN books b ON ib.book_id=b.id
                JOIN members m ON ib.member_id=m.id
                WHERE ib.return_date IS NULL AND ib.due_date < datetime('now','localtime')
                ORDER BY ib.due_date ASC
                """);
    }

    private Map<String, Object> one(String sql, Object... args) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql, args);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private int count(String sql, Object... args) {
        Integer result = jdbc.queryForObject(sql, Integer.class, args);
        return result == null ? 0 : result;
    }

    private int number(String sql) {
        Integer result = jdbc.queryForObject(sql, Integer.class);
        return result == null ? 0 : result;
    }

    private String nextId(String prefix, String table) {
        int max = number("SELECT COALESCE(MAX(CAST(SUBSTR(id,2) AS INTEGER)),0) FROM " + table);
        return prefix + String.format("%03d", max + 1);
    }

    private String format(LocalDateTime dateTime) {
        return dateTime.format(DATABASE_DATE_TIME);
    }

    public record OperationResult(boolean success, String message, String level) {
        public static OperationResult success(String message) {
            return new OperationResult(true, message, "success");
        }

        public static OperationResult warning(String message) {
            return new OperationResult(true, message, "warning");
        }

        public static OperationResult failure(String message) {
            return new OperationResult(false, message, "danger");
        }
    }

    public record StudentActivationResult(OperationResult result, String code) {
    }
}
