package com.example.customerservice.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class CustomerRestApi {
    @RequestMapping(path = "/customer",method = RequestMethod.GET)
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String,String> getCustomers(){
        //nokta
        return Map.of("name","foulane","email","chahid3ayan@gmail.com");
    }
}
