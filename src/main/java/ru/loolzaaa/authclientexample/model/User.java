package ru.loolzaaa.authclientexample.model;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class User {
    private Long id;
    private String login;
    private JsonNode config;
    private String name;
    private boolean enabled;
}
