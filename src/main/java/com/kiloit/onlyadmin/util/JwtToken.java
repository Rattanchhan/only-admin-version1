package com.kiloit.onlyadmin.util;

import com.kiloit.onlyadmin.security.CustomUserDetail;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.jpa.repository.Query;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtToken {
    private static final String ISSUER = "KILO-IT";
    public String createToken(JwtEncoder tokenJwtEncoder, JwtClaimsSet jwtClaimsSet) {
        return tokenJwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
    }

    public JwtClaimsSet generateAccessToken(Authentication authentication) {
        CustomUserDetail customUserDetail = (CustomUserDetail) authentication.getPrincipal();
        Instant now = Instant.now();
        String scope = customUserDetail.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        scope = scope.concat(" ").concat(customUserDetail.getRoleName());
        return  JwtClaimsSet.builder()
                .issuer(ISSUER)
                .issuedAt(now)
                .expiresAt(now.plus(7, ChronoUnit.DAYS))
                .subject(customUserDetail.getName())
                .id(customUserDetail.getId().toString())
                .claim("scope", scope)
                .claim("id", customUserDetail.getId())
                .claim("username", customUserDetail.getUsername())
                .claim("roleId", customUserDetail.getRoleId())
                .claim("email", customUserDetail.getEmail())
                .claim("phone", customUserDetail.getPhone())
                .claim("address", customUserDetail.getAddress())
                .claim("avatar", customUserDetail.getAvatar())
                .claim("roleName", customUserDetail.getRoleName())
                .build();
    }
    public JwtClaimsSet generateRefreshToken(Authentication authentication,String type) {
        if(type.equals("new-token")) {
            Map<String, Object> claims = ((Jwt) authentication.getPrincipal()).getClaims();
            String scope = claims.get("scope").toString();
            return JwtClaimsSet.builder()
                    .issuer(ISSUER)
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
                    .subject("Refresh Token")
                    .id(claims.get("id").toString())
                    .claim("scope", scope)
                    .claim("id", claims.get("id"))
                    .claim("username", claims.get("username"))
                    .claim("roleId", claims.get("roleId"))
                    .claim("email",claims.get("email"))
                    .claim("phone",claims.get("phone"))
                    .claim("address", claims.get("address"))
                    .claim("avatar", claims.get("avatar"))
                    .claim("roleName", claims.get("roleName"))
                    .build();
        }
        else {
            CustomUserDetail customUserDetail = (CustomUserDetail) authentication.getPrincipal();
            Instant now = Instant.now();
            String scope = customUserDetail.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));
            scope = scope.concat(" ").concat(customUserDetail.getRoleName());
            return JwtClaimsSet.builder()
                    .issuer(ISSUER)
                    .issuedAt(now)
                    .expiresAt(now.plus(30, ChronoUnit.DAYS))
                    .subject("Refresh Token")
                    .id(customUserDetail.getId().toString())
                    .claim("scope", scope)
                    .claim("id", customUserDetail.getId())
                    .claim("username", customUserDetail.getUsername())
                    .claim("roleId", customUserDetail.getRoleId())
                    .claim("email", customUserDetail.getEmail())
                    .claim("phone", customUserDetail.getPhone())
                    .claim("address", customUserDetail.getAddress())
                    .claim("avatar", customUserDetail.getAvatar())
                    .claim("roleName", customUserDetail.getRoleName())
                    .build();
        }
    }
}
