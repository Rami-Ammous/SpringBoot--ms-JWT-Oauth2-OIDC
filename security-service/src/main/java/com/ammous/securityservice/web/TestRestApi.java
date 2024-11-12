package com.ammous.securityservice.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @author Rami Ammous
 */
@RestController
public class TestRestApi {

    @GetMapping("dataTest")
    @PreAuthorize("hasAuthority('SCOPE_USER')")
    public Map<String, Object> dataTest(Authentication authentication) {
        return Map.of("message" , "Data test",
                "userName" , authentication.getName(),
                "authorities" , authentication.getAuthorities()
        );
    }

    @PostMapping ("/saveData")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String, String> saveData(Authentication authentication, String data) {
        return Map.of("dataSaved", data );
    }

}
