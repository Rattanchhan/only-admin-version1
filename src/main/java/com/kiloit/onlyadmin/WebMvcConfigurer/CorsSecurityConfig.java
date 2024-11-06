package com.kiloit.onlyadmin.WebMvcConfigurer;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "spring.cors")
@Data
@EnableMethodSecurity
public class CorsSecurityConfig {
    private List<String> allowedOrigins;
    private List<String> allowedHeader;
    private List<String> allowedMethod;
    private Boolean allowCredentials;
    private String maxAge;
}


