package ru.loolzaaa.sso.client.core.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class UserTest {

    @Test
    void testEquals() {
        User user1 = new User();
        user1.setLogin("TEST1");
        User user2 = new User();
        user2.setLogin("TEST2");
        User user3 = new User();
        user3.setLogin("TEST1");

        assertEquals(user1, user3);
        assertNotEquals(user1, user2);
        assertNotEquals(user2, user3);
    }
}