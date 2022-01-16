package com.example.demo.controller;

import com.example.demo.model.JwtResponse;
import com.example.demo.service.SecretService;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
public class SecretsController extends BaseController {

    @Autowired
    SecretService secretService;

    @RequestMapping(value = "/get-secrets", method = GET)
    public Map<String, String> getSecrets() {
        return secretService.getSecrets();
    }

    @RequestMapping(value = "/refresh-secrets", method = GET)
    public Map<String, String> refreshSecrets() {
        return secretService.refreshSecrets();
    }

    @RequestMapping(value = "/set-secrets", method = POST)
    public Map<String, String> setSecrets(@RequestBody Map<String, String> secrets) {
        secretService.setSecrets(secrets);
        return secretService.getSecrets();
    }

    @RequestMapping(value = "/dynamic-builder-specific", method = POST)
    public JwtResponse dynamicBuilderSpecific(@RequestBody Map<String, Object> claims) throws UnsupportedEncodingException {
        JwtBuilder builder = Jwts.builder();

        claims.forEach((key, value) -> {
            switch (key) {
                case "iss":
                    ensureType(key, value, String.class);
                    builder.setIssuer((String) value);
                    break;
                case "sub":
                    ensureType(key, value, String.class);
                    builder.setSubject((String) value);
                    break;
                case "aud":
                    ensureType(key, value, String.class);
                    builder.setAudience((String) value);
                    break;
                case "exp":
                    ensureType(key, value, Long.class);
                    builder.setExpiration(Date.from(Instant.ofEpochSecond(Long.parseLong(value.toString()))));
                    break;
                case "nbf":
                    ensureType(key, value, Long.class);
                    builder.setNotBefore(Date.from(Instant.ofEpochSecond(Long.parseLong(value.toString()))));
                    break;
                case "iat":
                    ensureType(key, value, Long.class);
                    builder.setIssuedAt(Date.from(Instant.ofEpochSecond(Long.parseLong(value.toString()))));
                    break;
                case "jti":
                    ensureType(key, value, String.class);
                    builder.setId((String) value);
                    break;
                default:
                    builder.claim(key, value);
            }
        });

        builder.signWith(SignatureAlgorithm.HS256, secretService.getHS256SecretBytes());

        return new JwtResponse(builder.compact());
    }

    private void ensureType(String registeredClaim, Object value, Class<?> expectedType) {
        boolean isCorrectType = expectedType.isInstance(value) || expectedType == Long.class && value instanceof Integer;

        if (!isCorrectType) {
            String msg = "Expected type: " + expectedType.getCanonicalName() + " for registered claim: '" + registeredClaim + "', but got value: " + value + " of type: " + value.getClass()
                    .getCanonicalName();
            throw new JwtException(msg);
        }
    }

}
