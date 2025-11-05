package com.example.pqc.jwt;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;

/**
 * CRYSTALS-Dilithium3 양자내성 서명 알고리즘을 사용하는 JWT 서명기 구현.
 *
 * 이 클래스는 Dilithium3를 사용하여 JWT 토큰에 서명하는 기능을 제공하여
 * 양자 컴퓨터 공격에 대한 내성을 갖도록 합니다.
 */
public class Dilithium3Signer {

    private static final Logger logger = LoggerFactory.getLogger(Dilithium3Signer.class);

    private final PrivateKey privateKey;

    /**
     * 주어진 개인키로 새로운 Dilithium3Signer를 생성합니다.
     *
     * @param privateKey 서명에 사용할 Dilithium3 개인키
     * @throws IllegalArgumentException 개인키가 null인 경우
     */
    public Dilithium3Signer(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        this.privateKey = privateKey;
        logger.debug("Dilithium3Signer initialized with key algorithm: {}", privateKey.getAlgorithm());
    }

    /**
     * Dilithium3 알고리즘을 사용하여 주어진 데이터에 서명합니다.
     *
     * @param data 서명할 데이터
     * @return 서명 바이트
     * @throws SignatureException 서명이 실패한 경우
     */
    public byte[] sign(byte[] data) throws SignatureException {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be null or empty");
        }

        try {
            logger.debug("Signing {} bytes of data", data.length);

            Signature signature = Signature.getInstance(
                Dilithium3Algorithm.SIGNATURE_ALGORITHM,
                Dilithium3Algorithm.BCPQC_PROVIDER
            );

            signature.initSign(privateKey);
            signature.update(data);
            byte[] signatureBytes = signature.sign();

            logger.debug("Signature generated: {} bytes", signatureBytes.length);
            return signatureBytes;

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            logger.error("Failed to get Dilithium signature algorithm", e);
            throw new SignatureException("Dilithium algorithm not available", e);
        } catch (InvalidKeyException e) {
            logger.error("Invalid private key", e);
            throw new SignatureException("Invalid private key for Dilithium3", e);
        }
    }

    /**
     * JWT 페이로드에 서명합니다.
     *
     * @param payload 서명할 JWT 페이로드 (일반적으로 header + "." + claims)
     * @return 바이트 배열 형태의 서명
     * @throws SignatureException 서명이 실패한 경우
     */
    public byte[] signJWT(String payload) throws SignatureException {
        if (payload == null || payload.isEmpty()) {
            throw new IllegalArgumentException("JWT payload cannot be null or empty");
        }

        logger.debug("Signing JWT payload: {} characters", payload.length());
        return sign(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * 이 서명기의 알고리즘 식별자를 반환합니다.
     *
     * @return 알고리즘 식별자 문자열
     */
    public String getAlgorithm() {
        return Dilithium3Algorithm.DILITHIUM3;
    }

    /**
     * 이 서명기가 사용하는 개인키를 반환합니다.
     *
     * @return 개인키
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
