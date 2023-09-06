package com.example.msauth.model.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor(staticName = "of")
@NoArgsConstructor
public class AuthCacheData {

    private static final long serialVersionUID = 1L;

    private AccessTokenClaimSet accessTokenClaimsSet;
    private String publicKey;
}
