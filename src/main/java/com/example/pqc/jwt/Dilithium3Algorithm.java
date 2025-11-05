package com.example.pqc.jwt;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

/**
 * CRYSTALS-Dilithium3 양자내성 서명 알고리즘을 위한 커스텀 JWT 알고리즘 식별자.
 *
 * Dilithium3으로 토큰에 서명할 때 JWT 헤더에 사용될 알고리즘 식별자를 정의합니다.
 */
public class Dilithium3Algorithm {

    /**
     * Dilithium3 알고리즘 식별자.
     * JWT 헤더에서 "DILITHIUM3"을 커스텀 알고리즘 이름으로 사용합니다.
     */
    public static final String DILITHIUM3 = "DILITHIUM3";

    /**
     * BouncyCastle PQC 프로바이더 이름.
     */
    public static final String BCPQC_PROVIDER = "BCPQC";

    /**
     * 서명 연산을 위한 알고리즘 이름.
     */
    public static final String SIGNATURE_ALGORITHM = "Dilithium";

    /**
     * 키 생성 알고리즘 이름.
     */
    public static final String KEYGEN_ALGORITHM = "Dilithium";

    /**
     * 주어진 알고리즘 식별자가 DILITHIUM3인지 검증합니다.
     *
     * @param algorithmIdentifier 검증할 알고리즘 식별자
     * @return 식별자가 DILITHIUM3이면 true, 그렇지 않으면 false
     */
    public static boolean isDilithium3(String algorithmIdentifier) {
        return DILITHIUM3.equals(algorithmIdentifier);
    }

    /**
     * Dilithium3의 JOSE 알고리즘 식별자를 반환합니다.
     *
     * @return 알고리즘 식별자 문자열
     */
    public static String getAlgorithmIdentifier() {
        return DILITHIUM3;
    }
}
