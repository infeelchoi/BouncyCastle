package com.example.pqc.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 양자내성 암호화를 위한 고수준 JWT 관리자.
 *
 * 이 클래스는 CRYSTALS-Dilithium3 양자내성 서명 알고리즘으로 서명된
 * JWT 토큰을 생성하고 검증하기 위한 간단한 API를 제공합니다.
 */
public class PQCJwtManager {

    private static final Logger logger = LoggerFactory.getLogger(PQCJwtManager.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final Dilithium3Signer signer;
    private final Dilithium3Verifier verifier;
    private final KeyPair keyPair;

    /**
     * 주어진 키 쌍으로 새로운 PQCJwtManager를 생성합니다.
     *
     * @param keyPair 서명 및 검증에 사용할 Dilithium3 키 쌍
     * @throws IllegalArgumentException 키 쌍이 null이거나 유효하지 않은 경우
     */
    public PQCJwtManager(KeyPair keyPair) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        if (!PQCKeyManager.validateKeyPair(keyPair)) {
            throw new IllegalArgumentException("Invalid key pair");
        }

        this.keyPair = keyPair;
        this.signer = new Dilithium3Signer(keyPair.getPrivate());
        this.verifier = new Dilithium3Verifier(keyPair.getPublic());

        logger.info("PQCJwtManager initialized with Dilithium3 algorithm");
    }

    /**
     * 주어진 클레임으로 JWT 토큰을 생성합니다.
     *
     * @param claims 토큰에 포함할 클레임 (subject, issuer, expiration 등)
     * @return 완전한 JWT 토큰 문자열 (header.payload.signature)
     * @throws Exception 토큰 생성이 실패한 경우
     */
    public String createToken(Map<String, Object> claims) throws Exception {
        if (claims == null) {
            claims = new HashMap<>();
        }

        logger.debug("Creating JWT token with {} claims", claims.size());

        // JWT 헤더 생성
        Map<String, Object> header = new HashMap<>();
        header.put("alg", Dilithium3Algorithm.DILITHIUM3);
        header.put("typ", "JWT");

        // 발행 시간이 없으면 추가
        if (!claims.containsKey("iat")) {
            claims.put("iat", System.currentTimeMillis() / 1000);
        }

        // 헤더와 페이로드 인코딩
        String encodedHeader = base64UrlEncode(objectMapper.writeValueAsString(header));
        String encodedPayload = base64UrlEncode(objectMapper.writeValueAsString(claims));

        // 서명 입력 생성
        String signingInput = encodedHeader + "." + encodedPayload;

        // 토큰 서명
        byte[] signature = signer.signJWT(signingInput);
        String encodedSignature = base64UrlEncode(signature);

        // 완전한 JWT 생성
        String jwt = signingInput + "." + encodedSignature;

        logger.info("JWT token created successfully (length: {} chars)", jwt.length());
        logger.debug("Token structure - Header: {} chars, Payload: {} chars, Signature: {} chars",
            encodedHeader.length(), encodedPayload.length(), encodedSignature.length());

        return jwt;
    }

    /**
     * JWT 토큰을 검증하고 파싱합니다.
     *
     * @param token 검증할 JWT 토큰
     * @return 토큰이 유효한 경우 클레임
     * @throws Exception 검증이 실패하거나 토큰이 유효하지 않은 경우
     */
    public Map<String, Object> validateToken(String token) throws Exception {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        logger.debug("Validating JWT token ({} chars)", token.length());

        // 토큰을 부분으로 분할
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format: expected 3 parts, got " + parts.length);
        }

        String encodedHeader = parts[0];
        String encodedPayload = parts[1];
        String encodedSignature = parts[2];

        // 서명 검증
        String signingInput = encodedHeader + "." + encodedPayload;
        byte[] signature = base64UrlDecode(encodedSignature);

        boolean isValid = verifier.verifyJWT(signingInput, signature);

        if (!isValid) {
            logger.warn("JWT signature verification failed");
            throw new SecurityException("Invalid JWT signature");
        }

        logger.debug("JWT signature verified successfully");

        // 헤더 파싱 및 검증
        String headerJson = new String(base64UrlDecode(encodedHeader), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> header = objectMapper.readValue(headerJson, Map.class);

        String algorithm = (String) header.get("alg");
        if (!Dilithium3Algorithm.DILITHIUM3.equals(algorithm)) {
            throw new SecurityException("Unsupported algorithm: " + algorithm);
        }

        // 클레임 파싱
        String payloadJson = new String(base64UrlDecode(encodedPayload), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = objectMapper.readValue(payloadJson, Map.class);

        // 만료 시간이 있으면 검증
        if (claims.containsKey("exp")) {
            long expiration = ((Number) claims.get("exp")).longValue();
            long currentTime = System.currentTimeMillis() / 1000;

            if (currentTime > expiration) {
                logger.warn("JWT token has expired (exp: {}, now: {})", expiration, currentTime);
                throw new SecurityException("JWT token has expired");
            }
        }

        logger.info("JWT token validated successfully with {} claims", claims.size());
        return claims;
    }

    /**
     * 표준 클레임으로 토큰을 생성합니다.
     *
     * @param subject 주체 (사용자 식별자)
     * @param issuer 발행자
     * @param expirationSeconds 현재로부터 만료까지의 시간(초)
     * @return JWT 토큰
     * @throws Exception 토큰 생성이 실패한 경우
     */
    public String createStandardToken(String subject, String issuer, long expirationSeconds) throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", subject);
        claims.put("iss", issuer);
        claims.put("iat", System.currentTimeMillis() / 1000);
        claims.put("exp", (System.currentTimeMillis() / 1000) + expirationSeconds);

        return createToken(claims);
    }

    /**
     * Base64 URL-safe 인코딩.
     *
     * @param data 인코딩할 데이터
     * @return Base64 URL-인코딩된 문자열
     */
    private String base64UrlEncode(String data) {
        return base64UrlEncode(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 바이트 배열을 위한 Base64 URL-safe 인코딩.
     *
     * @param data 인코딩할 데이터
     * @return Base64 URL-인코딩된 문자열
     */
    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Base64 URL-safe 디코딩.
     *
     * @param data Base64 URL-인코딩된 문자열
     * @return 디코딩된 바이트 배열
     */
    private byte[] base64UrlDecode(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    /**
     * 토큰 검증을 위한 공개키를 반환합니다.
     *
     * @return 공개키
     */
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    /**
     * 토큰 서명을 위한 개인키를 반환합니다.
     *
     * @return 개인키
     */
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    /**
     * 알고리즘 식별자를 반환합니다.
     *
     * @return 알고리즘 식별자 문자열
     */
    public String getAlgorithm() {
        return Dilithium3Algorithm.DILITHIUM3;
    }
}
