package com.kiloit.onlyadmin.model.user.respone.auth;

import com.kiloit.onlyadmin.security.CustomUserDetail;
import jakarta.persistence.Column;
import lombok.Builder;

@Builder
public record AuthResponse(
    
    String tokenType,
    CustomUserDetailResponse user,
    String accessToken,
    String refreshToken
){
    
}
