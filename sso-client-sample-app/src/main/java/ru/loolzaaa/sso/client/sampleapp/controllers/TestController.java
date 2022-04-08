package ru.loolzaaa.sso.client.sampleapp.controllers;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.model.User;

import java.util.Random;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class TestController {

    private final UserService userService;

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/get/test/{id}")
    public Test testGet(@PathVariable("id") int id) {
        Test test = new Test();
        test.setName("Name_" + id);
        test.setValue(new Random().nextInt());
        return test;
    }

    @PreAuthorize("hasAuthority('privilege1')")
    @PostMapping("/post/test/{id}")
    public Test testPost(@PathVariable("id") int id) {
        Test test = new Test();
        test.setName("Name_" + id);
        test.setValue(new Random().nextInt());
        return test;
    }

    @GetMapping("/get/test")
    public Test testUser() {
        User requestUser = userService.getRequestUser();
        Test test = new Test();
        test.setName(requestUser.getLogin());
        test.setValue(requestUser.getId().intValue());
        return test;
    }

    @Getter
    @Setter
    static class Test {
        private String name;
        private int value;
    }
}
