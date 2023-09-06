package com.example.msauth.util;

import com.example.msauth.exception.AuthException;
import com.example.msauth.model.constants.AuthConstants;
import com.example.msauth.model.constants.ExceptionConstants;
import com.example.msauth.model.jwt.AccessTokenClaimSet;
import com.example.msauth.model.jwt.RefreshTokenClaimSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

import static com.example.msauth.model.constants.AuthConstants.KEY_SIZE;
import static com.example.msauth.model.constants.AuthConstants.RSA;
import static com.example.msauth.model.constants.ExceptionConstants.USER_UNAUTHORIZED_CODE;
import static com.example.msauth.model.constants.ExceptionConstants.USER_UNAUTHORIZED_MESSAGE;

@Slf4j
@Component
public class JwtUtil {
    private final ObjectMapper objectMapper = new ObjectMapper();

    public KeyPair generateKeyPair(){
        try {
            var keyPairGen = KeyPairGenerator.getInstance(RSA);
            keyPairGen.initialize(KEY_SIZE);
            return keyPairGen.generateKeyPair();
        }catch (NoSuchAlgorithmException exception){
            log.error("ActionLog.generateKeyPair.error no such algorithm", exception);
            throw  new AuthException(USER_UNAUTHORIZED_MESSAGE, USER_UNAUTHORIZED_CODE, 401);
        }
    }

    public <T> String generateToken(T tokenClaimSet, PrivateKey privateKey) {

        SignedJWT signedJWT;
        try {
            signedJWT = generateSignedJWT(objectMapper.writeValueAsString(tokenClaimSet), privateKey);
        } catch (Exception e) {
            log.error("ActionLog.generateToken.error cannot generate token", e);
            throw new AuthException(USER_UNAUTHORIZED_MESSAGE, USER_UNAUTHORIZED_CODE, 401);
        }
        return signedJWT.serialize();
    }

    public void verifyToken(String token, RSAPublicKey publicKey) {

        try {
            var signedJwt = SignedJWT.parse(token);
            var verifier = new RSASSAVerifier(publicKey);

            if (!signedJwt.verify(verifier)) {
                log.error("ActionLog.verifyToken.error can't verify signedJwt");
                throw new AuthException(USER_UNAUTHORIZED_MESSAGE, USER_UNAUTHORIZED_CODE, 401);
            }
        } catch (ParseException | JOSEException e) {
            log.error("ActionLog.verifyToken.error can't parse token ", e);
            throw new AuthException(USER_UNAUTHORIZED_MESSAGE, USER_UNAUTHORIZED_CODE, 401);
        }
    }

    public Date generateSessionExpirationTime(Integer expirationMinutes) {
        return new Date(System.currentTimeMillis() + expirationMinutes * 60 * 1_000);
    }

    public boolean isRefreshTokenTimeExpired(RefreshTokenClaimSet refreshTokenClaimsSet) {
        return refreshTokenClaimsSet.getExpirationTime().before(new Date());
    }

    public boolean isRefreshTokenCountExpired(RefreshTokenClaimSet refreshTokenClaimsSet) {
        return refreshTokenClaimsSet.getCount() <= 0;
    }

    public AccessTokenClaimSet getClaimsFromAccessToken(String token) {

        AccessTokenClaimSet claimsSet;
        try {
            claimsSet = objectMapper.readValue(getClaimsFromToken(token).toString(), AccessTokenClaimSet.class);
        } catch (IOException | ParseException e) {
            log.error("ActionLog.getClaimsFromAccessToken.error can't parse access token", e);
            throw new AuthException(USER_UNAUTHORIZED_MESSAGE, USER_UNAUTHORIZED_CODE, 401);
        }
        return claimsSet;
    }

    public RefreshTokenClaimSet getClaimsFromRefreshToken(String token) {

        RefreshTokenClaimSet claimsSet;
        try {
            var claimsAsText = getClaimsFromToken(token).toString();
            log.info(claimsAsText);
            claimsSet = objectMapper.readValue(claimsAsText, RefreshTokenClaimSet.class);
        } catch (IOException | ParseException e) {
            log.error(e.getMessage());
            log.error("ActionLog.getClaimsFromRefreshToken.error can't parse refresh token", e);
            throw new AuthException(USER_UNAUTHORIZED_MESSAGE, USER_UNAUTHORIZED_CODE, 401);
        }
        return claimsSet;
    }

    private JWTClaimsSet getClaimsFromToken(String token) throws ParseException {
        return SignedJWT.parse(token).getJWTClaimsSet();
    }

    private SignedJWT generateSignedJWT(String tokenClaimSetJson, PrivateKey privateKey) throws JOSEException, ParseException {

        var jwtClaimsSet = JWTClaimsSet.parse(tokenClaimSetJson);
        var header = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(header, jwtClaimsSet);
        var signer = new RSASSASigner(privateKey);
        signedJWT.sign(signer);

        return signedJWT;
    }

    public boolean isTokenExpired(Date expirationTime) {
        return expirationTime.before(new Date());
    }
}
