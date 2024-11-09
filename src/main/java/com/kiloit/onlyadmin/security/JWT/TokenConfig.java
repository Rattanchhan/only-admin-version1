package com.kiloit.onlyadmin.security.JWT;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
public class TokenConfig {
    @Value("${spring.security.access-password}")
    private String password1;

    @Value("${spring.security.access-salt}")
    private String salt1;

    @Value("${spring.security.refresh-password}")
    private String password2;

    @Value("${spring.security.refresh-salt}")
    private String salt2;

    @Bean("accessTokenKeyPair")
    public KeyPair getAccessTokenKeyPair() throws GeneralSecurityException {
        return generateKeyPair(password1, salt1);
    }


    @Bean("refreshTokenKeyPair")
    public KeyPair getRefreshTokenKeyPair() throws GeneralSecurityException {
        return generateKeyPair(password2, salt2);
    }

    public KeyPair generateKeyPair(String password,String salt) throws GeneralSecurityException {

        byte[] seed = deriveSeedFromPasswordAndSalt(password, salt);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(seed);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    private byte[] deriveSeedFromPasswordAndSalt(String password, String accessSalt) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), accessSalt.getBytes(), 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

}
