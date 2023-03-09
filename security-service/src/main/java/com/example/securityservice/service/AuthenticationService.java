package com.example.securityservice.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthenticationService {
    //TODO: you must put the business logic here
    public Map<String, String> authenticate(String grantType,
                                            String username, String password,
                                            boolean withRefreshToken,
                                            String refreshToken){
        return null;
    }
}
