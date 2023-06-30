package ru.loolzaaa.sso.client.core.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.io.IOException;

public class SaveRequestUserAfterBasicAuthenticationFilter extends OncePerRequestFilter {

    private final UserService userService;

    public SaveRequestUserAfterBasicAuthenticationFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                Object principal = authentication.getPrincipal();
                if (principal instanceof org.springframework.security.core.userdetails.User) {
                    userService.saveRequestUser(createBasicUser((org.springframework.security.core.userdetails.User) principal));
                } else {
                    logger.warn("Incorrect user principal class: " + principal.getClass().getName());
                }
            }
            chain.doFilter(request, response);
        } finally {
            userService.clearRequestUser();
        }
    }

    private UserPrincipal createBasicUser(org.springframework.security.core.userdetails.User springUser) {
        User user = new User();
        user.setId(-1L);
        user.setLogin(springUser.getUsername());
        user.setName("BASIC");
        return new UserPrincipal(user);
    }
}
