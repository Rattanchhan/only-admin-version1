package com.kiloit.onlyadmin.util;

import com.kiloit.onlyadmin.security.JWT.JwtDecoderToken;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;


@RequiredArgsConstructor
@Service
public class GetUser {
    private final JwtDecoderToken jwtDecoderToken;

    public String getEmailUser() {
        return jwtDecoderToken.getClaimSet().get("iss").toString();
    }

    public String getRoleUser(){
        return jwtDecoderToken.getClaimSet().get("scope").toString().replace("ROLE_", "");
    }

}
