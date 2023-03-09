package com.example.securityservice.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestRestAPI {
    @GetMapping("/dataTest")
    @PreAuthorize("hasAnyAuthority('SCOPE_USER','SCOPE_ADMIN')")
    public Map<String,Object> dataTest(Authentication authentication){
        return Map.of("message","hello",
                "username",authentication.getName(),
                "authorities",authentication.getAuthorities());
    }

    @PostMapping("/savedData")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String,Object> saveData( @RequestBody String data){
        return Map.of("savedData",data);
    }
}
