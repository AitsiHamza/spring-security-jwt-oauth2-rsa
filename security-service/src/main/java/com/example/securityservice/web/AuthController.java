package com.example.securityservice.web;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@AllArgsConstructor
public class AuthController {
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private AuthenticationManager authenticationManager;
    private UserDetailsService userDetailsService;

    //TODO: you must put the business logic in AuthenticationService
    @PostMapping("/token")
    public ResponseEntity<Map<String,String>> jwtToken(String grantType,
                                                       String username, String password,
                                                       boolean withRefreshToken,
                                                       String refreshToken){
        String subject=null;
        String scope=null;

        if(grantType.equals("password")){
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

            scope=authentication.getAuthorities()
                    .stream().map(auth->auth.getAuthority())
                    .collect(Collectors.joining(" "));

            subject=authentication.getName();
        }else if(grantType.equals("refreshToken")){
            if(refreshToken.isBlank()) {
                return new ResponseEntity<>(Map.of("errorMessage","Refresh token is required!"), HttpStatus.UNAUTHORIZED);
            }

            Jwt decodedJwt = null;
            try {
                decodedJwt = jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("errorMessage",e.getMessage()), HttpStatus.UNAUTHORIZED);
            }

            subject = decodedJwt.getSubject();

            Collection<? extends GrantedAuthority> authorities = userDetailsService.loadUserByUsername(subject).getAuthorities();

            scope=authorities
                    .stream().map(auth->auth.getAuthority())
                    .collect(Collectors.joining(" "));
        }

        Map<String, String> mapTokens =new HashMap<>();

        Instant instant=Instant.now();
        JwtClaimsSet jwtClaimsSet= JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken?5:30, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

        mapTokens.put("accessToken", jwtAccessToken);

        if(withRefreshToken){
            JwtClaimsSet jwtClaimsSetRefresh= JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(withRefreshToken?5:30, ChronoUnit.MINUTES))
                    .issuer("security-service")
                    .build();
            String jwtRefreshToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();

            mapTokens.put("refreshToken",jwtRefreshToken);
        }
        return new ResponseEntity<>(mapTokens,HttpStatus.OK);
    }

    //@PostMapping("/token")
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
