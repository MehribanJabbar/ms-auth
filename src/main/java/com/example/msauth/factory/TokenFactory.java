package com.example.msauth.factory;

import com.example.msauth.model.constants.AuthConstants;
import com.example.msauth.model.jwt.AccessTokenClaimSet;
import com.example.msauth.model.jwt.RefreshTokenClaimSet;

import java.util.Date;

public class TokenFactory {

    public static AccessTokenClaimSet buildAccessTokenClaimsSet(Long userId, Date expirationTime){
        return AccessTokenClaimSet.builder()
                .iss(AuthConstants.ISSUER)
                .userId(userId)
                .createdTime(new Date())
                .expirationTime(expirationTime)
                .build();
    }

    public static RefreshTokenClaimSet buildRefreshTokenClaimsSet(Long userId, int refreshTokenExpirationCount, Date expirationTime){
        return RefreshTokenClaimSet.builder()
                .iss(AuthConstants.ISSUER)
                .userId(userId)
                .expirationTime(expirationTime)
                .count(refreshTokenExpirationCount)
                .build();
    }
}
