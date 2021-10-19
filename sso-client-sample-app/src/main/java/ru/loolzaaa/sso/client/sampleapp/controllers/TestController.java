package ru.loolzaaa.sso.client.sampleapp.controllers;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Random;

@RestController
@RequestMapping("/api")
public class TestController {

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

    @Getter
    @Setter
    static class Test {
        private String name;
        private int value;
    }
}
