package com.example.pqc.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;

/**
 * CRYSTALS-Dilithium3 양자내성 서명 알고리즘을 사용하는 JWT 서명 검증기 구현.
 *
 * 이 클래스는 Dilithium3를 사용하여 JWT 토큰 서명을 검증하는 기능을 제공하여
 * 양자 내성 토큰의 무결성과 진위성을 보장합니다.
 */
public class Dilithium3Verifier {

    private static final Logger logger = LoggerFactory.getLogger(Dilithium3Verifier.class);

    private final PublicKey publicKey;

    /**
     * 주어진 공개키로 새로운 Dilithium3Verifier를 생성합니다.
     *
     * @param publicKey 검증에 사용할 Dilithium3 공개키
     * @throws IllegalArgumentException 공개키가 null인 경우
     */
    public Dilithium3Verifier(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        this.publicKey = publicKey;
        logger.debug("Dilithium3Verifier initialized with key algorithm: {}", publicKey.getAlgorithm());
    }

    /**
     * Dilithium3 알고리즘을 사용하여 주어진 데이터에 대한 서명을 검증합니다.
     *
     * @param data 서명된 원본 데이터
     * @param signatureBytes 검증할 서명
     * @return 서명이 유효하면 true, 그렇지 않으면 false
     * @throws SignatureException 검증 프로세스가 실패한 경우
     */
    public boolean verify(byte[] data, byte[] signatureBytes) throws SignatureException {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        if (signatureBytes == null || signatureBytes.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }

        try {
            logger.debug("Verifying signature ({} bytes) against data ({} bytes)",
                signatureBytes.length, data.length);

            Signature signature = Signature.getInstance(
                Dilithium3Algorithm.SIGNATURE_ALGORITHM,
                Dilithium3Algorithm.BCPQC_PROVIDER
            );

            signature.initVerify(publicKey);
            signature.update(data);
            boolean isValid = signature.verify(signatureBytes);

            logger.debug("Signature verification result: {}", isValid);
            return isValid;

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            logger.error("Failed to get Dilithium signature algorithm", e);
            throw new SignatureException("Dilithium algorithm not available", e);
        } catch (InvalidKeyException e) {
            logger.error("Invalid public key", e);
            throw new SignatureException("Invalid public key for Dilithium3", e);
        }
    }

    /**
     * JWT 서명을 검증합니다.
     *
     * @param payload 서명된 JWT 페이로드 (일반적으로 header + "." + claims)
     * @param signatureBytes 검증할 서명 바이트
     * @return 서명이 유효하면 true, 그렇지 않으면 false
     * @throws SignatureException 검증이 실패한 경우
     */
    public boolean verifyJWT(String payload, byte[] signatureBytes) throws SignatureException {
        if (payload == null || payload.isEmpty()) {
            throw new IllegalArgumentException("JWT payload cannot be null or empty");
        }

        logger.debug("Verifying JWT payload: {} characters", payload.length());
        return verify(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8), signatureBytes);
    }

    /**
     * 이 검증기의 알고리즘 식별자를 반환합니다.
     *
     * @return 알고리즘 식별자 문자열
     */
    public String getAlgorithm() {
        return Dilithium3Algorithm.DILITHIUM3;
    }

    /**
     * 이 검증기가 사용하는 공개키를 반환합니다.
     *
     * @return 공개키
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }
}
