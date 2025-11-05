package com.example.pqc.jwt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Base64;

/**
 * 양자내성 암호화 연산을 위한 키 관리자.
 * PQC 키의 생성, 저장 및 직렬화를 처리합니다.
 */
public class PQCKeyManager {

    private static final Logger logger = LoggerFactory.getLogger(PQCKeyManager.class);

    static {
        // BouncyCastle 프로바이더가 등록되어 있는지 확인
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    /**
     * 새로운 Dilithium3 키 쌍을 생성합니다.
     *
     * @return Dilithium3 파라미터를 가진 새로운 KeyPair
     * @throws NoSuchAlgorithmException 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException 프로바이더를 사용할 수 없는 경우
     * @throws InvalidAlgorithmParameterException 파라미터가 유효하지 않은 경우
     */
    public static KeyPair generateDilithium3KeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        logger.info("Generating Dilithium3 key pair");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
            Dilithium3Algorithm.KEYGEN_ALGORITHM,
            Dilithium3Algorithm.BCPQC_PROVIDER
        );

        keyPairGenerator.initialize(DilithiumParameterSpec.dilithium3);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        logger.info("Dilithium3 key pair generated successfully");
        logger.debug("Public key size: {} bytes", keyPair.getPublic().getEncoded().length);
        logger.debug("Private key size: {} bytes", keyPair.getPrivate().getEncoded().length);

        return keyPair;
    }

    /**
     * 공개키를 Base64 문자열로 인코딩합니다.
     *
     * @param publicKey 인코딩할 공개키
     * @return Base64로 인코딩된 키의 문자열 표현
     */
    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * 개인키를 Base64 문자열로 인코딩합니다.
     *
     * @param privateKey 인코딩할 개인키
     * @return Base64로 인코딩된 키의 문자열 표현
     */
    public static String encodePrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * 키로부터 알고리즘 이름을 가져옵니다.
     *
     * @param key 검사할 키
     * @return 알고리즘 이름
     */
    public static String getKeyAlgorithm(Key key) {
        return key.getAlgorithm();
    }

    /**
     * 키의 크기를 바이트 단위로 가져옵니다.
     *
     * @param key 측정할 키
     * @return 인코딩된 키의 크기(바이트)
     */
    public static int getKeySize(Key key) {
        return key.getEncoded().length;
    }

    /**
     * 키 쌍이 올바르게 생성되었고 일치하는지 검증합니다.
     *
     * @param keyPair 검증할 키 쌍
     * @return 키 쌍이 유효하면 true
     */
    public static boolean validateKeyPair(KeyPair keyPair) {
        if (keyPair == null || keyPair.getPublic() == null || keyPair.getPrivate() == null) {
            logger.error("Key pair validation failed: null keys");
            return false;
        }

        String publicAlgorithm = keyPair.getPublic().getAlgorithm();
        String privateAlgorithm = keyPair.getPrivate().getAlgorithm();

        if (!publicAlgorithm.equals(privateAlgorithm)) {
            logger.error("Key pair validation failed: algorithm mismatch (public: {}, private: {})",
                publicAlgorithm, privateAlgorithm);
            return false;
        }

        logger.debug("Key pair validated successfully (algorithm: {})", publicAlgorithm);
        return true;
    }
}
