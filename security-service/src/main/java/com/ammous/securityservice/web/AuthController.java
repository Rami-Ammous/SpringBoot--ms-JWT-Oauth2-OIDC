package com.ammous.securityservice.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
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

/**
 * @author Rami Ammous
 */
@RestController
public class AuthController {

    private JwtEncoder jwtEncoder;
    private AuthenticationManager authenticationManager;
    private JwtDecoder jwtDecoder;
    private UserDetailsService userDetailsService;
    
    public AuthController(JwtEncoder jwtEncoder, AuthenticationManager authenticationManager, JwtDecoder jwtDecoder, UserDetailsService userDetailsService) {
        this.jwtEncoder = jwtEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, String>> jwTocken(
            String grandType,
            String username,
            String password,
            boolean withRefreshToken,
            String refreshToken) {

        String subject = null;
        String scope = null;

        if(grandType.equals("password")) {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            subject= authentication.getName();
            scope=authentication.getAuthorities()
                    .stream().map(aut -> aut.getAuthority()).collect(Collectors.joining(" "));
        }

        else if (grandType.equals("refreshToken")) {
            if (refreshToken==null) {
                return new ResponseEntity<>(Map.of( "errorMessage" , "Resfresh Token is required" ) , HttpStatus.UNAUTHORIZED);
            }
            Jwt decodeJWT = null;
            try {
                decodeJWT = jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of( "errorMessage" , e.getMessage() ) , HttpStatus.UNAUTHORIZED);
            }
            subject=decodeJWT.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            scope = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));

        }

        Map<String, String> idTocken = new HashMap<>();
        Instant instant = Instant.now();
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken==true ? 1 : 5, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope", scope)
                .build();
        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idTocken.put("access_token", jwtAccessToken);
        if (withRefreshToken) {
            JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(5 , ChronoUnit.MINUTES))
                    .issuer("security-service")
                    .build();
            String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
            idTocken.put("refresh_token", jwtRefreshToken);
        }

        return new ResponseEntity<>(idTocken, HttpStatus.OK);
    }
}
