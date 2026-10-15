package com.college.library.controller;

import com.college.library.service.LibraryService;
import com.college.library.service.LibraryService.OperationResult;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Map;

@Controller
public class LibraryController {
    private static final DateTimeFormatter DATABASE_DATE_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LibraryService library;

    public LibraryController(LibraryService library) {
        this.library = library;
    }

    @ModelAttribute("requestUri")
    public String requestUri(HttpServletRequest request) {
        return request.getRequestURI();
    }

    @ModelAttribute("userRole")
    public String userRole(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? "" : String.valueOf(session.getAttribute("userRole"));
    }

    @ModelAttribute("csrf")
    public CsrfToken csrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    }

    @GetMapping("/setup")
    public String setupPage(HttpServletRequest request, Model model) {
        if (!isLoopback(request)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        if (library.isBootstrapComplete()) {
            return "redirect:/login";
        }
        return "setup";
    }

    @PostMapping("/setup")
    public String completeSetup(@RequestParam String username, @RequestParam String password,
                                @RequestParam String confirm_password, HttpServletRequest request,
                                RedirectAttributes redirect) {
        if (!isLoopback(request)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        if (!password.equals(confirm_password)) {
            addMessage(redirect, "The passwords do not match.", "danger");
            return "redirect:/setup";
        }
        OperationResult result = library.completeInitialSetup(username, password);
        apply(result, redirect);
        return result.success() ? "redirect:/login" : "redirect:/setup";
    }

    private boolean isLoopback(HttpServletRequest request) {
        try {
            return request.getRemoteAddr() != null
                    && java.net.InetAddress.getByName(request.getRemoteAddr()).isLoopbackAddress();
        } catch (java.net.UnknownHostException exception) {
            return false;
        }
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String loginPage(HttpSession session) {
        if ("ADMIN".equals(session.getAttribute("userRole"))) {
            return "redirect:/dashboard";
        }
        return "STUDENT".equals(session.getAttribute("userRole"))
                ? "redirect:/student/dashboard"
                : "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                        HttpSession session, HttpServletRequest request, RedirectAttributes redirect) {
        String remoteAddress = request.getRemoteAddr();
        if (library.loginBlocked("ADMIN", username, remoteAddress)) {
            addMessage(redirect, "Invalid username or password. Try again in 15 minutes.", "danger");
            return "redirect:/login";
        }
        Map<String, Object> admin = library.authenticateAdmin(username, password);
        if (admin != null) {
            library.clearLoginFailures("ADMIN", username, remoteAddress);
            session.invalidate();
            session = request.getSession(true);
            session.setAttribute("userRole", "ADMIN");
            session.setAttribute("adminId", ((Number) admin.get("id")).longValue());
            session.setAttribute("username", admin.get("username"));
            session.setAttribute("adminType", admin.get("role"));
            redirect.addFlashAttribute("message", "Welcome back, " + admin.get("username") + "!");
            redirect.addFlashAttribute("messageType", "success");
            return "redirect:/dashboard";
        }
        library.recordFailedLogin("ADMIN", username, remoteAddress);
        redirect.addFlashAttribute("message", "Invalid username or password.");
        redirect.addFlashAttribute("messageType", "danger");
        return "redirect:/login";
    }

    @PostMapping("/logout")
    public String logout(HttpSession session, RedirectAttributes redirect) {
        session.invalidate();
        redirect.addFlashAttribute("message", "You have been logged out.");
        redirect.addFlashAttribute("messageType", "info");
        return "redirect:/login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        Map<String, Object> summary = library.dashboard();
        model.addAllAttributes(summary);
        model.addAttribute("recentIssues", library.recentIssues());
        model.addAttribute("monitoring", library.monitoringSummary());
        model.addAttribute("recentAdminLogins", library.recentAdminLogins());
        model.addAttribute("nowText", LocalDateTime.now().format(DATABASE_DATE_TIME));
        return "dashboard";
    }

    @GetMapping("/admin/accounts")
    public String adminAccounts(Model model) {
        model.addAttribute("admins", library.adminAccounts());
        model.addAttribute("monitoring", library.monitoringSummary());
        return "admin_accounts";
    }

    @GetMapping("/admin/accounts/new")
    public String newAdminPage() {
        return "add_admin";
    }

    @PostMapping("/admin/accounts")
    public String createAdmin(@RequestParam String username, @RequestParam String password,
                              @RequestParam String confirm_password, HttpSession session,
                              RedirectAttributes redirect) {
        if (!password.equals(confirm_password)) {
            addMessage(redirect, "The passwords do not match.", "danger");
            return "redirect:/admin/accounts/new";
        }
        long creatorId = ((Number) session.getAttribute("adminId")).longValue();
        OperationResult result = library.createSubAdmin(username, password, creatorId);
        apply(result, redirect);
        return result.success() ? "redirect:/admin/accounts" : "redirect:/admin/accounts/new";
    }

    @PostMapping("/admin/accounts/{adminId}/password")
    public String resetAdminPassword(@PathVariable long adminId, @RequestParam String password,
                                     @RequestParam String confirm_password, HttpSession session,
                                     RedirectAttributes redirect) {
        if (!password.equals(confirm_password)) {
            addMessage(redirect, "The passwords do not match.", "danger");
            return "redirect:/admin/accounts";
        }
        apply(library.resetAdminPassword(adminId, password), redirect);
        return "redirect:/admin/accounts";
    }

    @PostMapping("/admin/accounts/{adminId}/status")
    public String setAdminStatus(@PathVariable long adminId, @RequestParam boolean enabled,
                                 HttpSession session, RedirectAttributes redirect) {
        long currentAdminId = ((Number) session.getAttribute("adminId")).longValue();
        apply(library.setAdminEnabled(adminId, enabled, currentAdminId), redirect);
        return "redirect:/admin/accounts";
    }

    @GetMapping("/admin/students")
    public String monitoredStudents(@RequestParam(defaultValue = "") String q, Model model) {
        model.addAttribute("students", library.monitoredStudents(q.trim()));
        model.addAttribute("query", q);
        model.addAttribute("monitoring", library.monitoringSummary());
        return "admin_students";
    }

    @GetMapping("/admin/students/{memberId}")
    public String monitoredStudent(@PathVariable String memberId, Model model,
                                   RedirectAttributes redirect) {
        Map<String, Object> member = library.member(memberId);
        if (member == null) {
            addMessage(redirect, "Student record not found.", "danger");
            return "redirect:/admin/students";
        }
        model.addAttribute("member", member);
        model.addAttribute("loans", library.studentLoans(memberId));
        return "admin_student_detail";
    }

    @PostMapping("/admin/students/{memberId}/activation")
    public String createStudentActivation(@PathVariable String memberId, HttpSession session,
                                          RedirectAttributes redirect) {
        long adminId = ((Number) session.getAttribute("adminId")).longValue();
        LibraryService.StudentActivationResult activation =
                library.createStudentActivationCode(memberId, adminId);
        if (activation.code() != null) {
            redirect.addFlashAttribute("activationCode", activation.code());
        }
        apply(activation.result(), redirect);
        return "redirect:/admin/students/" + memberId;
    }

    @GetMapping("/view_books")
    public String viewBooks(@RequestParam(defaultValue = "") String q,
                            @RequestParam(defaultValue = "") String category, Model model) {
        model.addAttribute("books", library.books(q.trim(), category.trim()));
        model.addAttribute("categories", LibraryService.BOOK_CATEGORIES);
        model.addAttribute("query", q);
        model.addAttribute("categoryFilter", category);
        return "view_books";
    }

    @GetMapping("/add_book")
    public String addBookPage(Model model) {
        model.addAttribute("categories", LibraryService.BOOK_CATEGORIES);
        return "add_book";
    }

    @PostMapping("/add_book")
    public String addBook(@RequestParam String title, @RequestParam String author,
                          @RequestParam String category, @RequestParam int quantity,
                          RedirectAttributes redirect) {
        if (title.isBlank() || author.isBlank() || quantity < 1) {
            addMessage(redirect, "Enter a title, author, and a positive number of copies.", "danger");
            return "redirect:/add_book";
        }
        apply(library.saveBook(null, title.trim(), author.trim(), category, quantity), redirect);
        return "redirect:/view_books";
    }

    @GetMapping("/edit_book/{bookId}")
    public String editBookPage(@PathVariable String bookId, Model model, RedirectAttributes redirect) {
        Map<String, Object> book = library.book(bookId);
        if (book == null) {
            addMessage(redirect, "Book not found.", "danger");
            return "redirect:/view_books";
        }
        model.addAttribute("book", book);
        model.addAttribute("categories", LibraryService.BOOK_CATEGORIES);
        return "edit_book";
    }

    @PostMapping("/edit_book/{bookId}")
    public String editBook(@PathVariable String bookId, @RequestParam String title,
                           @RequestParam String author, @RequestParam String category,
                           @RequestParam int quantity, RedirectAttributes redirect) {
        if (title.isBlank() || author.isBlank() || quantity < 0) {
            addMessage(redirect, "Enter a title, author, and a non-negative quantity.", "danger");
        } else {
            apply(library.saveBook(bookId, title.trim(), author.trim(), category, quantity), redirect);
        }
        return "redirect:/view_books";
    }

    @PostMapping("/delete_book/{bookId}")
    public String deleteBook(@PathVariable String bookId, RedirectAttributes redirect) {
        apply(library.deleteBook(bookId), redirect);
        return "redirect:/view_books";
    }

    @GetMapping("/view_members")
    public String viewMembers(@RequestParam(defaultValue = "") String q,
                              @RequestParam(defaultValue = "") String department, Model model) {
        model.addAttribute("members", library.members(q.trim(), department.trim()));
        model.addAttribute("departments", LibraryService.DEPARTMENTS);
        model.addAttribute("query", q);
        model.addAttribute("departmentFilter", department);
        model.addAttribute("issueCounts", library.activeIssueCounts());
        return "view_members";
    }

    @GetMapping("/add_member")
    public String addMemberPage(Model model) {
        model.addAttribute("departments", LibraryService.DEPARTMENTS);
        return "add_member";
    }

    @PostMapping("/add_member")
    public String addMember(@RequestParam String name, @RequestParam String roll_number,
                            @RequestParam String department, @RequestParam(defaultValue = "") String email,
                            @RequestParam(defaultValue = "") String phone,
                            @RequestParam(defaultValue = "") String address,
                            @RequestParam(defaultValue = "") String password,
                            RedirectAttributes redirect) {
        if (name.isBlank() || roll_number.isBlank()
                || (!password.isBlank() && password.length() < 12)) {
            addMessage(redirect, "Name and roll number are required; an optional password must be at least 12 characters.", "danger");
            return "redirect:/add_member";
        }
        OperationResult result = library.saveMember(null, name.trim(), roll_number, department,
                email.trim(), phone.trim(), address.trim(), password);
        apply(result, redirect);
        return result.success() ? "redirect:/view_members" : "redirect:/add_member";
    }

    @GetMapping("/edit_member/{memberId}")
    public String editMemberPage(@PathVariable String memberId, Model model, RedirectAttributes redirect) {
        Map<String, Object> member = library.member(memberId);
        if (member == null) {
            addMessage(redirect, "Member not found.", "danger");
            return "redirect:/view_members";
        }
        model.addAttribute("member", member);
        model.addAttribute("departments", LibraryService.DEPARTMENTS);
        model.addAttribute("accountEnabled", ((Number) member.get("account_enabled")).intValue() == 1);
        return "edit_member";
    }

    @PostMapping("/edit_member/{memberId}")
    public String editMember(@PathVariable String memberId, @RequestParam String name,
                             @RequestParam String roll_number, @RequestParam String department,
                             @RequestParam(defaultValue = "") String email,
                             @RequestParam(defaultValue = "") String phone,
                             @RequestParam(defaultValue = "") String address,
                             @RequestParam(defaultValue = "") String password,
                             RedirectAttributes redirect) {
        if (name.isBlank() || roll_number.isBlank()) {
            addMessage(redirect, "Name and roll number are required.", "danger");
        } else if (!password.isBlank() && password.length() < 12) {
            addMessage(redirect, "Student passwords must be at least 12 characters.", "danger");
        } else {
            apply(library.saveMember(memberId, name.trim(), roll_number, department,
                    email.trim(), phone.trim(), address.trim(), password), redirect);
        }
        return "redirect:/view_members";
    }

    @PostMapping("/delete_member/{memberId}")
    public String deleteMember(@PathVariable String memberId, RedirectAttributes redirect) {
        apply(library.deleteMember(memberId), redirect);
        return "redirect:/view_members";
    }

    @GetMapping("/issue_book")
    public String issueBookPage(Model model) {
        populateIssueForm(model);
        return "issue_book";
    }

    @PostMapping("/issue_book")
    public String issueBook(@RequestParam String book_id, @RequestParam String member_id,
                            @RequestParam String issue_date, @RequestParam String issue_time,
                            Model model, RedirectAttributes redirect) {
        try {
            LocalDateTime issuedAt = LocalDateTime.of(LocalDate.parse(issue_date), LocalTime.parse(issue_time));
            OperationResult result = library.issueBook(book_id, member_id, issuedAt);
            if (!result.success()) {
                addMessage(redirect, result.message(), result.level());
                return "redirect:/issue_book";
            }
            apply(result, redirect);
            return "redirect:/view_issued_books";
        } catch (DateTimeParseException ex) {
            model.addAttribute("message", "Enter a valid issue date and time.");
            model.addAttribute("messageType", "danger");
            populateIssueForm(model);
            return "issue_book";
        }
    }

    @GetMapping("/view_issued_books")
    public String viewIssuedBooks(@RequestParam(defaultValue = "all") String status,
                                  @RequestParam(defaultValue = "") String q, Model model) {
        if (!java.util.Set.of("all", "active", "returned", "overdue").contains(status)) {
            status = "all";
        }
        model.addAttribute("issuedBooks", library.issuedBooks(status, q.trim()));
        model.addAttribute("statusFilter", status);
        model.addAttribute("query", q);
        model.addAttribute("nowText", LocalDateTime.now().format(DATABASE_DATE_TIME));
        return "view_issued_books";
    }

    @GetMapping("/return_book")
    public String returnBookPage(Model model) {
        model.addAttribute("activeIssues", library.activeIssues());
        populateNow(model);
        return "return_book";
    }

    @PostMapping("/return_book")
    public String returnBook(@RequestParam long issue_id, @RequestParam String return_date,
                             @RequestParam String return_time, Model model, RedirectAttributes redirect) {
        try {
            LocalDateTime returnedAt = LocalDateTime.of(LocalDate.parse(return_date), LocalTime.parse(return_time));
            OperationResult result = library.returnBook(issue_id, returnedAt);
            if (!result.success()) {
                apply(result, redirect);
                return "redirect:/return_book";
            }
            apply(result, redirect);
            return "redirect:/view_issued_books";
        } catch (DateTimeParseException ex) {
            model.addAttribute("message", "Enter a valid return date and time.");
            model.addAttribute("messageType", "danger");
            model.addAttribute("activeIssues", library.activeIssues());
            populateNow(model);
            return "return_book";
        }
    }

    @GetMapping("/overdue_books")
    public String overdueBooks(Model model) {
        model.addAttribute("overdue", library.overdueBooks());
        return "overdue_books";
    }

    @GetMapping("/student")
    public String studentHome() {
        return "redirect:/student/dashboard";
    }

    @GetMapping("/student/login")
    public String studentLoginPage(HttpSession session) {
        return "STUDENT".equals(session.getAttribute("userRole"))
                ? "redirect:/student/dashboard"
                : ("ADMIN".equals(session.getAttribute("userRole")) ? "redirect:/dashboard" : "student_login");
    }

    @GetMapping("/student/register")
    public String studentRegistrationPage(HttpSession session) {
        if ("STUDENT".equals(session.getAttribute("userRole"))) {
            return "redirect:/student/dashboard";
        }
        return "student_register";
    }

    @PostMapping("/student/register")
    public String registerStudent(@RequestParam String roll_number, @RequestParam String email,
                                  @RequestParam String activation_code, @RequestParam String password,
                                  @RequestParam String confirm_password,
                                  RedirectAttributes redirect) {
        if (!password.equals(confirm_password)) {
            addMessage(redirect, "The passwords do not match.", "danger");
            return "redirect:/student/register";
        }
        Map<String, Object> result = library.registerStudent(roll_number, email, activation_code, password);
        String level = Boolean.TRUE.equals(result.get("success")) ? "success" : "danger";
        addMessage(redirect, (String) result.get("message"), level);
        return Boolean.TRUE.equals(result.get("success"))
                ? "redirect:/student/login" : "redirect:/student/register";
    }

    @PostMapping("/student/login")
    public String studentLogin(@RequestParam String roll_number, @RequestParam String password,
                               HttpSession session, HttpServletRequest request, RedirectAttributes redirect) {
        String remoteAddress = request.getRemoteAddr();
        if (library.loginBlocked("STUDENT", roll_number, remoteAddress)) {
            addMessage(redirect, "Invalid roll number or password. Try again in 15 minutes.", "danger");
            return "redirect:/student/login";
        }
        Map<String, Object> member = library.authenticateStudent(roll_number, password);
        if (member == null) {
            library.recordFailedLogin("STUDENT", roll_number, remoteAddress);
            addMessage(redirect, "Invalid roll number or password. Ask your librarian to set or reset your password.", "danger");
            return "redirect:/student/login";
        }
        library.clearLoginFailures("STUDENT", roll_number, remoteAddress);
        session.invalidate();
        HttpSession studentSession = request.getSession(true);
        studentSession.setAttribute("userRole", "STUDENT");
        studentSession.setAttribute("memberId", member.get("id"));
        studentSession.setAttribute("username", member.get("name"));
        addMessage(redirect, "Welcome, " + member.get("name") + "!", "success");
        return "redirect:/student/dashboard";
    }

    @PostMapping("/student/logout")
    public String studentLogout(HttpSession session, RedirectAttributes redirect) {
        session.invalidate();
        addMessage(redirect, "You have been logged out.", "info");
        return "redirect:/student/login";
    }

    @GetMapping("/student/dashboard")
    public String studentDashboard(HttpSession session, Model model) {
        String memberId = (String) session.getAttribute("memberId");
        Map<String, Object> member = library.member(memberId);
        if (member == null) {
            session.invalidate();
            return "redirect:/student/login";
        }
        model.addAttribute("member", member);
        model.addAttribute("summary", library.studentSummary(memberId));
        model.addAttribute("loans", library.studentLoans(memberId));
        model.addAttribute("nowText", LocalDateTime.now().format(DATABASE_DATE_TIME));
        return "student_dashboard";
    }

    @GetMapping("/student/books")
    public String studentBooks(@RequestParam(defaultValue = "") String q,
                               @RequestParam(defaultValue = "") String category, Model model) {
        model.addAttribute("books", library.books(q.trim(), category.trim()));
        model.addAttribute("categories", LibraryService.BOOK_CATEGORIES);
        model.addAttribute("query", q);
        model.addAttribute("categoryFilter", category);
        return "student_books";
    }

    @GetMapping("/student/loans")
    public String studentLoans(HttpSession session, Model model) {
        String memberId = (String) session.getAttribute("memberId");
        model.addAttribute("loans", library.studentLoans(memberId));
        model.addAttribute("nowText", LocalDateTime.now().format(DATABASE_DATE_TIME));
        return "student_loans";
    }

    private void populateIssueForm(Model model) {
        model.addAttribute("books", library.availableBooks());
        model.addAttribute("members", library.allMembers());
        populateNow(model);
    }

    private void populateNow(Model model) {
        LocalDateTime now = LocalDateTime.now();
        model.addAttribute("today", now.toLocalDate().toString());
        model.addAttribute("currentTime", now.toLocalTime().format(DateTimeFormatter.ofPattern("HH:mm")));
    }

    private void apply(OperationResult result, RedirectAttributes redirect) {
        addMessage(redirect, result.message(), result.level());
    }

    private void addMessage(RedirectAttributes redirect, String message, String type) {
        redirect.addFlashAttribute("message", message);
        redirect.addFlashAttribute("messageType", type);
    }

}
