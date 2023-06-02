package ru.loolzaaa.sso.client.core.dto;

import ru.loolzaaa.sso.client.core.model.BaseUserConfig;

public class CreateUserRequestDTO {

    private static final long serialVersionUID = 4246511047852879657L;

    private String login;
    private String name;
    private BaseUserConfig config;

    public CreateUserRequestDTO() {
    }

    public CreateUserRequestDTO(String login, String name, BaseUserConfig config) {
        this.login = login;
        this.name = name;
        this.config = config;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public BaseUserConfig getConfig() {
        return config;
    }

    public void setConfig(BaseUserConfig config) {
        this.config = config;
    }
}
