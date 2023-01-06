package ru.loolzaaa.sso.client.core.context;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.loolzaaa.sso.client.core.model.User;

import static org.junit.jupiter.api.Assertions.*;

class UserStoreTest {

    UserStore userStore;

    @BeforeEach
    void setUp() {
        userStore = new UserStore();
    }

    @Test
    void shouldCorrectProcessUser() {
        User requestUser = userStore.getRequestUser();
        assertNull(requestUser);

        final long id = 123;
        final String login = "TEST";
        final User user = new User();
        user.setId(id);
        user.setLogin(login);
        userStore.saveRequestUser(user);

        requestUser = userStore.getRequestUser();
        assertNotNull(requestUser);
        assertEquals(requestUser.getId(), id);
        assertEquals(requestUser.getLogin(), login);

        userStore.clearRequestUser();

        requestUser = userStore.getRequestUser();
        assertNull(requestUser);
    }
}