package ru.loolzaaa.sso.client.core.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import ru.loolzaaa.sso.client.core.context.UserService;

import java.util.List;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SaveRequestUserAfterBasicAuthenticationFilterTest {

    @Mock
    UserService userService;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    FilterChain chain;

    SaveRequestUserAfterBasicAuthenticationFilter underTest;

    @BeforeEach
    void setUp() {
        underTest = new SaveRequestUserAfterBasicAuthenticationFilter(userService);
    }

    @Test
    void shouldSkipSavingUserIfAuthenticationIsNull() throws Exception {
        SecurityContextHolder.createEmptyContext();

        underTest.doFilterInternal(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verify(userService, times(0)).saveRequestUser(any());
        verify(userService).clearRequestUser();
    }

    @Test
    void shouldSkipSavingUserIfUserIsNotAuthenticated() throws Exception {
        SecurityContextHolder.createEmptyContext();
        UsernamePasswordAuthenticationToken unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated(null, null);
        SecurityContextHolder.getContext().setAuthentication(unauthenticated);

        underTest.doFilterInternal(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verify(userService, times(0)).saveRequestUser(any());
        verify(userService).clearRequestUser();
    }

    @Test
    void shouldSaveUserIfUserAuthenticated() throws Exception {
        User user = new User("USER", "", List.of());
        SecurityContextHolder.createEmptyContext();
        UsernamePasswordAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(
                user, null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authenticated);

        underTest.doFilterInternal(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verify(userService).saveRequestUser(any());
        verify(userService).clearRequestUser();
    }
}