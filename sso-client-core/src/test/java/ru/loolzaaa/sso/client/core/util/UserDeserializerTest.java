package ru.loolzaaa.sso.client.core.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith({MockitoExtension.class})
class UserDeserializerTest {

    UserDeserializer userDeserializer;

    @BeforeEach
    void setUp() {
        userDeserializer = new UserDeserializer(User.class, BaseUserConfig.class);
    }

    @Test
    void shouldCorrectDeserializeUser() throws Exception {
        final String json = "{\"id\":111, \"login\":\"USER\", \"name\":\"NAME\", \"config\": {\"roles\":[\"ROLE_USER\"], \"privileges\": [\"EDITOR\", \"VIEWER\"]}}";
        JsonParser jsonParser = new ObjectMapper().createParser(json);

        User user = userDeserializer.deserialize(jsonParser, null);

        assertThat(user)
                .isNotNull()
                .hasFieldOrPropertyWithValue("id", 111L)
                .hasFieldOrPropertyWithValue("login", "USER")
                .hasFieldOrPropertyWithValue("name", "NAME")
                .extracting("config")
                .isNotNull();
        BaseUserConfig config = user.getConfig();
        assertThat(config.getRoles())
                .isNotNull()
                .hasSize(1)
                .contains("ROLE_USER");
        assertThat(config.getPrivileges())
                .isNotNull()
                .hasSize(2)
                .contains("EDITOR", "VIEWER");
    }
}