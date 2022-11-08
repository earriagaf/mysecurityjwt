package com.tr.mexico.mysecurityjwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

@Component
public class JwtHelper {
    
    private final Key key;
    
    public JwtHelper(@Value("${jwt.secret}") String secret) {
        key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    public String createToken(String sub, Map<String, Object> claims) {
        return Jwts.builder()
                .setSubject(sub)
                .addClaims(claims)
                .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.MINUTES)))
                .signWith(key)
                .compact();
    }
    
    public Map<String, Object> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
