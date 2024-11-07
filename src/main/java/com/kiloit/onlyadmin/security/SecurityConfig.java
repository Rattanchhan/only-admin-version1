package com.kiloit.onlyadmin.security;
import com.kiloit.onlyadmin.WebMvcConfigurer.CorsSecurityConfig;
import com.kiloit.onlyadmin.exception.CustomAuthenticationEntryPoint;
import com.kiloit.onlyadmin.security.JWT.RolePermissionService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String[] PUBLIC_ROUTE = {"/api/v1/auth/**"};
    private final UserDetailsService userDetailsService;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final RolePermissionService rolePermissionService;
    private final CorsSecurityConfig corsSecurityConfig;

    @Bean
    DaoAuthenticationProvider configureDaoAuthenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
       return new BCryptPasswordEncoder();
    }
    @Bean
    public JwtAuthenticationProvider configAuthenticationProvider(@Qualifier("refreshTokenJwtDecoder")JwtDecoder refreshTokenJwtDecoder){
        return new JwtAuthenticationProvider(refreshTokenJwtDecoder);
    }
    @Bean
    SecurityFilterChain configureApiSecurity(HttpSecurity httpSecurity,@Qualifier("accessTokenJwtDecoder") JwtDecoder jwtDecoder) throws Exception{
        httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults());
        httpSecurity.authorizeHttpRequests(authorize -> authorize.requestMatchers(PUBLIC_ROUTE).permitAll());
        httpSecurity.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoder)
                        .jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .authenticationEntryPoint(customAuthenticationEntryPoint));
        httpSecurity.sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return httpSecurity.build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new CustomJwtGrantedAuthoritiesConverter(rolePermissionService));
        return converter;
    }
   @Bean
   CorsConfigurationSource corsConfigurationSource() {
       CorsConfiguration configuration = new CorsConfiguration();
       configuration.setAllowedOriginPatterns(List.of(corsSecurityConfig.getAllowedOrigins().split(",")));
       configuration.setAllowedMethods(List.of(corsSecurityConfig.getAllowedMethod().split(",")));
       configuration.setAllowedHeaders(List.of(corsSecurityConfig.getAllowedHeader().split(",")));
       configuration.setAllowCredentials(corsSecurityConfig.getAllowCredentials());
       configuration.setMaxAge(Long.parseLong(corsSecurityConfig.getMaxAge()));

       UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
       source.registerCorsConfiguration("/**", configuration);
       return source;
   }

}
