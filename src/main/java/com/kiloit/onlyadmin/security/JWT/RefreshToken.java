package com.kiloit.onlyadmin.security.JWT;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Component;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Component
@RequiredArgsConstructor
public class RefreshToken {
    private static final String PRIVATE_KEY_FILE = "refreshTokenPrivateKey.pem";
    private static final String PUBLIC_KEY_FILE = "refreshTokenPublicKey.pem";
    private final TokenConfig tokenConfig;

    @Bean(("refreshTokenKeyPair"))
    public KeyPair accessTokenKeyPairConfig() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
       return tokenConfig.getKeyPair(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE);
    }

    @Bean("refreshTokenRSAKey")
    RSAKey refreshTokenRSAKey(@Qualifier("refreshTokenKeyPair")KeyPair keyPair){
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
               .privateKey(keyPair.getPrivate())
               .keyID(UUID.randomUUID().toString())
               .build();
    }

    @Bean("refreshTokenJwtDecoder")
    JwtDecoder refreshTokenJwtDecoder(@Qualifier("refreshTokenRSAKey")RSAKey rsaKey) throws JOSEException{
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
    }

    @Bean("refreshTokenJwkSource")
    JWKSource <SecurityContext> refreshTokenJwkSource(@Qualifier("refreshTokenRSAKey")RSAKey rsaKey){
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector,securityContext)-> jwkSelector.select(jwkSet);
    }

    @Bean("refreshTokenJwtEncoder")
    JwtEncoder refreshTokenJwtEncoder(@Qualifier("refreshTokenJwkSource")JWKSource<SecurityContext> jwkSource){
        return new  NimbusJwtEncoder(jwkSource);
    }
}