package com.college.library.config;

import com.college.library.service.LibraryService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class LoginInterceptor implements HandlerInterceptor {
    private final LibraryService library;

    public LoginInterceptor(LibraryService library) {
        this.library = library;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        HttpSession session = request.getSession(false);
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (path.startsWith("/css/") || path.startsWith("/image/")
                || path.startsWith("/videos/") || path.equals("/error")
                || path.equals("/favicon.ico")) {
            return true;
        }
        if (path.equals("/setup")) {
            if (request.getRemoteAddr() != null
                    && java.net.InetAddress.getByName(request.getRemoteAddr()).isLoopbackAddress()) {
                return true;
            }
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        if (!library.isBootstrapComplete()) {
            response.sendRedirect(request.getContextPath() + "/setup");
            return false;
        }
        if (path.equals("/login") || path.equals("/student/login") || path.equals("/student/register")) {
            return true;
        }

        String role = session == null ? null : (String) session.getAttribute("userRole");
        if (path.startsWith("/student/") || path.equals("/student")) {
            if ("STUDENT".equals(role)) {
                return true;
            }
            response.sendRedirect(request.getContextPath()
                    + ("ADMIN".equals(role) ? "/dashboard" : "/student/login"));
            return false;
        }

        if ("STUDENT".equals(role)) {
            response.sendRedirect(request.getContextPath() + "/student/dashboard");
            return false;
        }
        if (!"ADMIN".equals(role)) {
            response.sendRedirect(request.getContextPath() + "/login");
            return false;
        }
        Object adminId = session.getAttribute("adminId");
        if (!(adminId instanceof Number id) || !library.isAdminEnabled(id.longValue())) {
            session.invalidate();
            response.sendRedirect(request.getContextPath() + "/login");
            return false;
        }
        return true;
    }
}
