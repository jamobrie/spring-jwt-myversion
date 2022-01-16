package com.example.demo.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.MacProvider;
import io.jsonwebtoken.lang.Assert;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class SecretService {

    private Map<String, String> secrets = new HashMap<>();

    private final SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
        @Override
        public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
            return Base64.getDecoder().decode(secrets.get(header.getAlgorithm()));
        }
    };

    @PostConstruct
    public void setup() {
        refreshSecrets();
    }

    public SigningKeyResolver getSigningKeyResolver() {
        return signingKeyResolver;
    }

    public Map<String, String> getSecrets() {
        return secrets;
    }

    public void setSecrets(Map<String, String> secrets) {
        Assert.notNull(secrets);
        Assert.hasText(secrets.get(SignatureAlgorithm.HS256.getValue()));
        this.secrets = secrets;
    }

    public byte[] getHS256SecretBytes() {
        return Base64.getDecoder().decode(secrets.get(SignatureAlgorithm.HS256.getValue()));
    }

    public Map<String, String> refreshSecrets() {
        SecretKey key = MacProvider.generateKey(SignatureAlgorithm.HS256);
        secrets.put(SignatureAlgorithm.HS256.getValue(), Base64.getEncoder().encodeToString(key.getEncoded()));
        return secrets;
    }
}
