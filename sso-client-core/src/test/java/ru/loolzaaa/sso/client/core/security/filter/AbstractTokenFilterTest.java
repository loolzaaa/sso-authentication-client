package ru.loolzaaa.sso.client.core.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import ru.loolzaaa.sso.client.core.application.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AbstractTokenFilterTest {

    @Mock
    UserService userService;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    FilterChain chain;

    AbstractTokenFilter<String> tokenFilter;

    @BeforeEach
    void setUp() {
        tokenFilter = new FakeTokenFilter(userService);
    }

    @Test
    void shouldContinueFilteringIfRequestUriIsIgnored() throws Exception {
        AuthorizationManager authorizationManager = mock(AuthorizationManager.class);
        AuthorizationDecision authorizationDecision = mock(AuthorizationDecision.class);
        when(authorizationManager.check(any(), any())).thenReturn(authorizationDecision);
        when(authorizationDecision.isGranted()).thenReturn(true);
        when(req.getRequestURL()).thenReturn(new StringBuffer("/"));
        tokenFilter.setPermitAllAuthorizationManager(authorizationManager);

        tokenFilter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verifyNoInteractions(userService);
    }

    @Test
    void shouldContinueFilteringIfExceptionWhileExtractingTokenData() throws Exception {
        ((FakeTokenFilter) tokenFilter).exceptionWhenExtract = true;

        tokenFilter.doFilterInternal(req, resp, chain);

        assertThat(((FakeTokenFilter)tokenFilter).extracted).isTrue();
        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verifyNoInteractions(userService);
    }

    @Test
    void shouldInvokeInvalidTokenDataHandler() throws Exception {
        ((FakeTokenFilter) tokenFilter).nullWhenExtract = true;

        tokenFilter.doFilterInternal(req, resp, chain);

        assertThat(((FakeTokenFilter)tokenFilter).invalidHandled).isTrue();
        verifyNoMoreInteractions(chain);
        verifyNoInteractions(userService);
    }

    @Test
    void shouldSaveUserInSystemIfLoginIsNotNullAndCorrectUser() throws Exception {
        ArgumentCaptor<UserPrincipal> userPrincipalCaptor = ArgumentCaptor.forClass(UserPrincipal.class);
        SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());

        tokenFilter.doFilterInternal(req, resp, chain);

        verify(userService).saveRequestUser(userPrincipalCaptor.capture());
        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verify(userService).clearRequestUser();
        assertThat(userPrincipalCaptor.getValue()).isNotNull();
        assertThat(userPrincipalCaptor.getValue())
                .extracting("user")
                .isNotNull()
                .extracting("login")
                .isEqualTo("LOGIN");
    }

    @Test
    void shouldUseApplicationRegisterHook() throws Exception {
        ArgumentCaptor<UserPrincipal> userPrincipalCaptor = ArgumentCaptor.forClass(UserPrincipal.class);
        SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
        SsoClientApplicationRegister applicationRegister = mock(SsoClientApplicationRegister.class);
        tokenFilter.addApplicationRegisters(List.of(applicationRegister));

        tokenFilter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verify(userService).clearRequestUser();
        verify(applicationRegister).register(userPrincipalCaptor.capture());
        assertThat(userPrincipalCaptor.getValue())
                .extracting("user")
                .isNotNull()
                .extracting("login")
                .isEqualTo("LOGIN");
    }

    static class FakeTokenFilter extends AbstractTokenFilter<String> {

        boolean extracted = false;
        boolean exceptionWhenExtract = false;
        boolean nullWhenExtract = false;

        boolean invalidHandled = false;

        public FakeTokenFilter(UserService userService) {
            super(userService);
        }

        @Override
        protected String extractTokenData(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            extracted = true;
            if (exceptionWhenExtract) {
                throw new IllegalArgumentException();
            }
            return nullWhenExtract ? null : "EXTRACTED";
        }

        @Override
        protected UserData processTokenData(HttpServletRequest req, String tokenData) {
            return new UserData("LOGIN", List.of("ROLE1", "PRIVILEGE1"));
        }

        @Override
        protected void handleInvalidTokenData(HttpServletRequest req, HttpServletResponse resp, FilterChain chain) throws IOException {
            invalidHandled = true;
        }
    }
}