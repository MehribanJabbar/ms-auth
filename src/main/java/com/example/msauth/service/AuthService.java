package com.example.msauth.service;

import com.example.msauth.client.UserClient;
import com.example.msauth.dto.SignInDto;
import com.example.msauth.dto.TokenDto;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${jwt.refreshToken.expiration.count}")
    private Integer refreshTokenExpirationTime;

    private final TokenService tokenService;
    private final UserClient userClient;

    public TokenDto signIn(SignInDto dto) {
        var user = userClient.getUserByUsername(dto.getUsername());
        return tokenService.generateToken(user.getId(), refreshTokenExpirationTime);
    }

    public void verifyToken(String accessToken) {
        tokenService.validateToken(accessToken);
    }

    public TokenDto refreshToken(String refreshToken) {
        return tokenService.refreshTokens(refreshToken);
    }

}
