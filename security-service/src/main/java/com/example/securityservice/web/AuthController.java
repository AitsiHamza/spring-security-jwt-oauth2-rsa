package com.example.securityservice.web;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@AllArgsConstructor
public class AuthController {
    private JwtEncoder jwtEncoder;
    private AuthenticationManager authenticationManager;

    @PostMapping("/token")
    public Map<String,String> jwtToken(String username,String password,boolean withRefreshToken){
        Map<String, String> mapTokens =new HashMap<>();

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        Instant instant=Instant.now();
        String scope=authentication.getAuthorities()
                .stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet= JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken?5:30, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

        mapTokens.put("accessToken", jwtAccessToken);

        if(withRefreshToken){
            JwtClaimsSet jwtClaimsSetRefresh= JwtClaimsSet.builder()
                    .subject(authentication.getName())
                    .issuedAt(instant)
                    .expiresAt(instant.plus(withRefreshToken?5:30, ChronoUnit.MINUTES))
                    .issuer("security-service")
                    .build();
            String jwtRefreshToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();

            mapTokens.put("refreshToken",jwtRefreshToken);
        }
        return mapTokens;
    }

    //@PostMapping("/token")
    public Map<String,String> jwtToken(String username,String password){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        Instant instant=Instant.now();
        String scope=authentication.getAuthorities()
                .stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet= JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuedAt(instant)
                .issuer("security-service")
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        return Map.of("accessToken",jwtAccessToken);
    }

    //@PostMapping("/token")
    public Map<String,String> jwtToken(Authentication authentication){
        Instant instant=Instant.now();
        String scope=authentication.getAuthorities()
                .stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet= JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuedAt(instant)
                .issuer("security-service")
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        return Map.of("accessToken",jwtAccessToken);
    }
}
