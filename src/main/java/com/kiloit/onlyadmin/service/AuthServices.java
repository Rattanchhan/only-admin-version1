package com.kiloit.onlyadmin.service;
import java.util.*;

import com.kiloit.onlyadmin.security.CustomUserDetail;
import com.kiloit.onlyadmin.util.JwtToken;
import com.kiloit.onlyadmin.util.MailSeverTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.stereotype.Service;
import com.kiloit.onlyadmin.base.BaseService;
import com.kiloit.onlyadmin.base.StructureRS;
import com.kiloit.onlyadmin.constant.MessageConstant;
import com.kiloit.onlyadmin.database.entity.PasswordResetEntity;
import com.kiloit.onlyadmin.database.entity.RoleEntity;
import com.kiloit.onlyadmin.database.entity.UserEntity;
import com.kiloit.onlyadmin.database.entity.UserVerification;
import com.kiloit.onlyadmin.database.repository.PasswordResetRepository;
import com.kiloit.onlyadmin.database.repository.RoleRepository;
import com.kiloit.onlyadmin.database.repository.UserRepository;
import com.kiloit.onlyadmin.database.repository.UserVerificationRepository;
import com.kiloit.onlyadmin.exception.httpstatus.BadRequestException;
import com.kiloit.onlyadmin.model.user.mapper.UserMapper;
import com.kiloit.onlyadmin.model.user.request.auth.LoginRequest;
import com.kiloit.onlyadmin.model.user.request.auth.RefreshTokenRequest;
import com.kiloit.onlyadmin.model.user.request.auth.RegisterRequest;
import com.kiloit.onlyadmin.model.user.request.auth.ResetPasswordRequest;
import com.kiloit.onlyadmin.model.user.request.auth.SendVerificationRequest;
import com.kiloit.onlyadmin.model.user.request.auth.VerificationRequest;
import com.kiloit.onlyadmin.model.user.request.auth.VerifyCode;
import com.kiloit.onlyadmin.model.user.respone.auth.AuthResponse;
import com.kiloit.onlyadmin.model.user.respone.auth.RegisterResponse;
import com.kiloit.onlyadmin.util.RandomUntil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import jakarta.transaction.Transactional;
import java.time.*;
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServices extends BaseService{
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserVerificationRepository userVerificationRepository;
    private final DaoAuthenticationProvider daoAuthenticationProvider;
    private final JwtEncoder accessTokenJwtEncoder;
    private final JwtEncoder refreshTokenJwtEncoder;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final PasswordResetRepository  passwordResetRepository;
    private final JwtToken jwtToken;
    private final MailSeverTemplate mailSeverTemplate;

    @Transactional
    public StructureRS register(RegisterRequest registerRequest) {
        if(userRepository.existsByPhone(registerRequest.phone()))
            throw new BadRequestException(MessageConstant.REGISTERPROPERTY.PHONE_IS_NOT_VALID);
        if(userRepository.existsByEmail(registerRequest.email()))
            throw new BadRequestException(MessageConstant.REGISTERPROPERTY.EMAIL_IS_EXISTING);
        if(userRepository.existsByPhone(registerRequest.username()))
            throw new BadRequestException(MessageConstant.REGISTERPROPERTY.USERNAME_IS_NOT_VALID);
        if(!registerRequest.confirmPassword().equals(registerRequest.password()))
            throw new BadRequestException(MessageConstant.CREDENTIAL.PASSWORD_NOT_MATCH);
        
        UserEntity user = userMapper.fromRegisterRequest(registerRequest);
        Optional<RoleEntity> role = roleRepository.findByCodeAndDeletedAtNull("USER");
        if(role.isEmpty()) throw new BadRequestException(MessageConstant.ROLE.ROLE_NOT_FOUND);
        user.setIsVerification(false);
        user.setPassword(passwordEncoder.encode(registerRequest.password()));
        user.setRole(role.get());
        user.setCreatedAt(Instant.now());
        userRepository.save(user);
        return response(RegisterResponse.builder()
                .message(MessageConstant.REGISTERPROPERTY.REGISTER_HAS_BEEN_SUCCESSFULLY)
                .email(registerRequest.email()).build());
    }

    public StructureRS sendVerification(String email){
        String codeRandom= RandomUntil.random6Digits();
        UserEntity user = userRepository
                .findByEmailAndIsVerificationAndDeletedAtNull(email,false)
                .orElseThrow(()-> new BadRequestException(MessageConstant.REGISTERPROPERTY.EMAIL_HAS_NOT_BEEN_FOUND));
        UserVerification userVerification = new UserVerification();
        userVerification.setUser(user);
        userVerification.setVerifiedCode(codeRandom);
        userVerification.setExpiryTime(LocalTime.now().plusMinutes(5));
        userVerificationRepository.save(userVerification);
        return mailSeverTemplate.prepareTemplateMail(email, user, codeRandom,"User Verification");
    }

    @Transactional
    public StructureRS verify(VerificationRequest verificationRequest) {
        UserEntity user = userRepository.findByEmailAndIsVerificationAndDeletedAtNull(verificationRequest
                .email(),false)
                .orElseThrow(()-> new BadRequestException(MessageConstant.REGISTERPROPERTY.EMAIL_HAS_NOT_BEEN_FOUND));
        UserVerification verification = userVerificationRepository
                .findByUserAndVerifiedCode(user,verificationRequest.verifiedCode())
                .orElseThrow(()-> new BadRequestException(MessageConstant.CREDENTIAL.VERIFY_CODE_HAS_BEEN_EXPRIED));
        if(LocalTime.now().isAfter(verification.getExpiryTime()))
            throw new BadRequestException(MessageConstant.CREDENTIAL.VERIFY_CODE_HAS_BEEN_EXPRIED);
        user.setIsVerification(true);
        userRepository.save(user);
        userVerificationRepository.delete(verification);
        return response();
    }

    public StructureRS resendVerification(SendVerificationRequest sendVerificationRequest) {
        String codeRandom= RandomUntil.random6Digits();
        UserEntity user = userRepository.findByEmailAndIsVerificationAndDeletedAtNull(sendVerificationRequest.email(),false)
                .orElseThrow(()-> new BadRequestException(MessageConstant.REGISTERPROPERTY.EMAIL_HAS_NOT_BEEN_FOUND));
        UserVerification verification = userVerificationRepository
                .findByUser(user)
                .orElseThrow(()-> new BadRequestException(MessageConstant.CREDENTIAL.VERIFY_CODE_HAS_BEEN_EXPRIED));
        verification.setVerifiedCode(codeRandom);
        verification.setExpiryTime(LocalTime.now().plusSeconds(60));
        userVerificationRepository.save(verification);
        return mailSeverTemplate.prepareTemplateMail(user.getEmail(), user, codeRandom,"User Verification");
    }

    public StructureRS login(LoginRequest loginRequest) {
        if(userRepository.existsByEmailAndIsVerificationAndDeletedAtNull(loginRequest.email(),true)){
            try{
                Authentication authentication= new UsernamePasswordAuthenticationToken(loginRequest.email(),loginRequest.password());
                authentication = daoAuthenticationProvider.authenticate(authentication);
                if(!authentication.isAuthenticated()) throw new BadRequestException(MessageConstant.CREDENTIAL.INVALID_EMAIL_OR_PASSWORD);
                return response(AuthResponse.builder()
                        .user(userMapper.from((CustomUserDetail) authentication.getPrincipal()))
                        .accessToken(jwtToken.createToken(accessTokenJwtEncoder, jwtToken.generateAccessToken(authentication)))
                        .refreshToken(jwtToken.createToken(refreshTokenJwtEncoder, jwtToken.generateRefreshToken(authentication,"null")))
                        .tokenType("Bearer").build());
            }catch(AuthenticationException e){
                throw new BadRequestException(MessageConstant.CREDENTIAL.INVALID_EMAIL_OR_PASSWORD);
            }
        } else throw new BadRequestException(MessageConstant.REGISTERPROPERTY.USERNAME_IS_NOT_VALID);
    }

    public StructureRS refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String accessToken;
        String refreshToken= refreshTokenRequest.refreshToken();
        Authentication authentication = new BearerTokenAuthenticationToken(refreshTokenRequest.refreshToken());
        authentication=jwtAuthenticationProvider.authenticate(authentication);
        if(Duration.between(Instant.now(), ((Jwt)authentication.getPrincipal()).getExpiresAt()).toDays()<=1) {
            refreshToken=jwtToken.createToken(accessTokenJwtEncoder, jwtToken.generateRefreshToken(authentication,"new-token"));
        }
        accessToken = jwtToken.createToken(accessTokenJwtEncoder, jwtToken.generateRefreshToken(authentication,"new-token"));
        return response(AuthResponse.builder().tokenType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken).build());
    }

    public StructureRS resetPassword(ResetPasswordRequest resetPasswordRequest){
        UserEntity user = userRepository.findByEmailAndIsVerificationAndDeletedAtNull(resetPasswordRequest.email(),true)
                .orElseThrow(()-> new BadRequestException(MessageConstant.REGISTERPROPERTY.EMAIL_HAS_NOT_BEEN_FOUND));
        PasswordResetEntity passwordResetEntity = passwordResetRepository.findByUser(user);
        String verifyCode = RandomUntil.random6Digits();

        if(passwordResetEntity==null){
            passwordResetEntity = new PasswordResetEntity();
            passwordResetEntity.setCode(verifyCode);
            passwordResetEntity.setUser(user);
        }
        else{
            passwordResetEntity.setCode(verifyCode);
        }
        passwordResetEntity.setExpiryTime(LocalTime.now().plusMinutes(5));
        passwordResetRepository.save(passwordResetEntity);
        return mailSeverTemplate.prepareTemplateMail(resetPasswordRequest.email(), user, verifyCode,"Password reset request");
    }

    @Transactional
    public StructureRS handlePasswordReset(VerifyCode verifyCode){
        Optional<PasswordResetEntity> passwordReset = passwordResetRepository.findByCode(verifyCode.code());
        if (passwordReset.isEmpty()) throw new BadRequestException(MessageConstant.CREDENTIAL.VERIFY_CODE_HAS_BEEN_EXPRIED);
        UserEntity user = passwordReset.get().getUser();
        user.setPassword(passwordEncoder.encode(verifyCode.password()));
        userRepository.save(user);
        passwordResetRepository.delete(passwordReset.get());
        return response(MessageConstant.RESET_PASSWORD_SUCCESSFULLY);
    }
    
}
