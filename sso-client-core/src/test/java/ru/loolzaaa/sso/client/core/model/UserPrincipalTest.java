package ru.loolzaaa.sso.client.core.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UserPrincipalTest {
    @Test
    void shouldCorrectDeserializeWithJsonCreator() throws Exception {
        String json = "{\"user\":{\"id\":1,\"login\":\"admin\"},\"property\":123}";

        UserPrincipal userPrincipal = new ObjectMapper()
                .readerFor(UserPrincipal.class)
                .readValue(json);

        assertThat(userPrincipal).isNotNull();
        assertThat(userPrincipal.getUser()).isNotNull();
        assertThat(userPrincipal.getUser().getId()).isEqualTo(1L);
        assertThat(userPrincipal.getUser().getLogin()).isEqualTo("admin");
    }

    @Test
    void shouldCorrectValuesOfUnusedFields() {
        UserPrincipal userPrincipal = new UserPrincipal(null);

        assertThat(userPrincipal.getPassword()).isNull();
        assertThat(userPrincipal.isAccountNonExpired()).isTrue();
        assertThat(userPrincipal.isAccountNonLocked()).isTrue();
        assertThat(userPrincipal.isCredentialsNonExpired()).isTrue();
        assertThat(userPrincipal.isEnabled()).isTrue();
    }

    @Test
    void shouldReturnUsernameByUserLogin() {
        final String login = "SUPER_LOGIN";
        User user = new User();
        user.setLogin(login);
        UserPrincipal userPrincipal = new UserPrincipal(user);

        String username = userPrincipal.getUsername();

        assertThat(username).isEqualTo(login);
    }
}