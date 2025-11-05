import com.example.pqc.jwt.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

/**
 * 양자내성 암호화 JWT 구현을 위한 포괄적인 테스트 모음.
 * JWT 토큰과 CRYSTALS-Dilithium3 서명 알고리즘 통합을 테스트합니다.
 */
public class PQCJwtTest {

    private static KeyPair keyPair;
    private static PQCJwtManager jwtManager;

    @BeforeAll
    public static void setUp() throws Exception {
        // 테스트용 Dilithium3 키 쌍 생성
        keyPair = PQCKeyManager.generateDilithium3KeyPair();
        jwtManager = new PQCJwtManager(keyPair);
    }

    @Test
    @DisplayName("Dilithium3 키 쌍 생성 테스트")
    public void testKeyPairGeneration() throws Exception {
        KeyPair testKeyPair = PQCKeyManager.generateDilithium3KeyPair();

        assertNotNull(testKeyPair, "키 쌍은 null이 아니어야 합니다");
        assertNotNull(testKeyPair.getPublic(), "공개키는 null이 아니어야 합니다");
        assertNotNull(testKeyPair.getPrivate(), "개인키는 null이 아니어야 합니다");
        assertTrue(testKeyPair.getPublic().getAlgorithm().contains("DILITHIUM"),
            "공개키는 Dilithium 알고리즘을 사용해야 합니다");
        assertTrue(testKeyPair.getPrivate().getAlgorithm().contains("DILITHIUM"),
            "개인키는 Dilithium 알고리즘을 사용해야 합니다");

        assertTrue(PQCKeyManager.validateKeyPair(testKeyPair),
            "키 쌍은 유효해야 합니다");
    }

    @Test
    @DisplayName("커스텀 클레임으로 JWT 토큰 생성 테스트")
    public void testCreateToken() throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user123");
        claims.put("name", "John Doe");
        claims.put("role", "admin");

        String token = jwtManager.createToken(claims);

        assertNotNull(token, "토큰은 null이 아니어야 합니다");
        assertFalse(token.isEmpty(), "토큰은 비어있지 않아야 합니다");

        // JWT는 점으로 구분된 3개 부분을 가져야 함
        String[] parts = token.split("\\.");
        assertEquals(3, parts.length, "JWT는 3개 부분을 가져야 합니다 (header.payload.signature)");

        // 각 부분은 비어있지 않아야 함
        assertTrue(parts[0].length() > 0, "헤더는 비어있지 않아야 합니다");
        assertTrue(parts[1].length() > 0, "페이로드는 비어있지 않아야 합니다");
        assertTrue(parts[2].length() > 0, "서명은 비어있지 않아야 합니다");
    }

    @Test
    @DisplayName("유효한 토큰으로 JWT 토큰 검증 테스트")
    public void testValidateValidToken() throws Exception {
        Map<String, Object> originalClaims = new HashMap<>();
        originalClaims.put("sub", "user456");
        originalClaims.put("email", "user@example.com");
        originalClaims.put("exp", (System.currentTimeMillis() / 1000) + 3600); // 1 hour expiration

        String token = jwtManager.createToken(originalClaims);
        Map<String, Object> validatedClaims = jwtManager.validateToken(token);

        assertNotNull(validatedClaims, "Validated claims should not be null");
        assertEquals("user456", validatedClaims.get("sub"),
            "Subject should match");
        assertEquals("user@example.com", validatedClaims.get("email"),
            "Email should match");
        assertTrue(validatedClaims.containsKey("iat"),
            "Token should contain issued-at time");
    }

    @Test
    @DisplayName("만료된 토큰으로 JWT 토큰 검증 테스트")
    public void testValidateExpiredToken() throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user789");
        claims.put("exp", (System.currentTimeMillis() / 1000) - 60); // Expired 1 minute ago

        String token = jwtManager.createToken(claims);

        SecurityException exception = assertThrows(SecurityException.class, () -> {
            jwtManager.validateToken(token);
        }, "Validation should throw SecurityException for expired token");

        assertTrue(exception.getMessage().contains("expired"),
            "Exception message should mention expiration");
    }

    @Test
    @DisplayName("변조된 페이로드로 JWT 토큰 검증 테스트")
    public void testValidateTamperedToken() throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user999");
        claims.put("role", "user");

        String token = jwtManager.createToken(claims);

        // Tamper with the token by modifying the payload
        String[] parts = token.split("\\.");
        String tamperedPayload = parts[1] + "tampered";
        String tamperedToken = parts[0] + "." + tamperedPayload + "." + parts[2];

        SecurityException exception = assertThrows(SecurityException.class, () -> {
            jwtManager.validateToken(tamperedToken);
        }, "Validation should throw SecurityException for tampered token");

        assertTrue(exception.getMessage().contains("signature"),
            "Exception message should mention signature validation");
    }

    @Test
    @DisplayName("잘못된 형식으로 JWT 토큰 검증 테스트")
    public void testValidateInvalidFormatToken() {
        String invalidToken = "invalid.token";

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            jwtManager.validateToken(invalidToken);
        }, "Validation should throw IllegalArgumentException for invalid format");

        assertTrue(exception.getMessage().contains("3 parts"),
            "Exception message should mention expected format");
    }

    @Test
    @DisplayName("표준 토큰 생성 테스트")
    public void testCreateStandardToken() throws Exception {
        String token = jwtManager.createStandardToken("user111", "PQC-Test-Issuer", 3600);

        assertNotNull(token, "Token should not be null");

        Map<String, Object> claims = jwtManager.validateToken(token);

        assertEquals("user111", claims.get("sub"), "Subject should match");
        assertEquals("PQC-Test-Issuer", claims.get("iss"), "Issuer should match");
        assertTrue(claims.containsKey("exp"), "Token should have expiration");
        assertTrue(claims.containsKey("iat"), "Token should have issued-at time");

        // Verify expiration is in the future
        long exp = ((Number) claims.get("exp")).longValue();
        long now = System.currentTimeMillis() / 1000;
        assertTrue(exp > now, "Expiration should be in the future");
    }

    @Test
    @DisplayName("Dilithium3Signer 직접 사용 테스트")
    public void testDilithium3Signer() throws Exception {
        Dilithium3Signer signer = new Dilithium3Signer(keyPair.getPrivate());

        String testData = "Test message for signing";
        byte[] signature = signer.signJWT(testData);

        assertNotNull(signature, "Signature should not be null");
        assertTrue(signature.length > 0, "Signature should have content");
        assertEquals(Dilithium3Algorithm.DILITHIUM3, signer.getAlgorithm(),
            "Algorithm should be DILITHIUM3");
    }

    @Test
    @DisplayName("Dilithium3Verifier 직접 사용 테스트")
    public void testDilithium3Verifier() throws Exception {
        Dilithium3Signer signer = new Dilithium3Signer(keyPair.getPrivate());
        Dilithium3Verifier verifier = new Dilithium3Verifier(keyPair.getPublic());

        String testData = "Test message for verification";
        byte[] signature = signer.signJWT(testData);

        boolean isValid = verifier.verifyJWT(testData, signature);
        assertTrue(isValid, "Signature should be valid");

        // Test with modified data
        String modifiedData = "Modified test message";
        boolean isInvalid = verifier.verifyJWT(modifiedData, signature);
        assertFalse(isInvalid, "Signature should be invalid for modified data");
    }

    @Test
    @DisplayName("키 인코딩 및 크기 테스트")
    public void testKeyEncoding() {
        String encodedPublicKey = PQCKeyManager.encodePublicKey(keyPair.getPublic());
        String encodedPrivateKey = PQCKeyManager.encodePrivateKey(keyPair.getPrivate());

        assertNotNull(encodedPublicKey, "Encoded public key should not be null");
        assertNotNull(encodedPrivateKey, "Encoded private key should not be null");
        assertTrue(encodedPublicKey.length() > 0, "Encoded public key should have content");
        assertTrue(encodedPrivateKey.length() > 0, "Encoded private key should have content");

        int publicKeySize = PQCKeyManager.getKeySize(keyPair.getPublic());
        int privateKeySize = PQCKeyManager.getKeySize(keyPair.getPrivate());

        assertTrue(publicKeySize > 0, "Public key size should be positive");
        assertTrue(privateKeySize > 0, "Private key size should be positive");
    }

    @Test
    @DisplayName("다중 토큰 생성 및 검증 테스트")
    public void testMultipleTokens() throws Exception {
        // Create multiple tokens with different claims
        for (int i = 0; i < 5; i++) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "user" + i);
            claims.put("index", i);

            String token = jwtManager.createToken(claims);
            Map<String, Object> validatedClaims = jwtManager.validateToken(token);

            assertEquals("user" + i, validatedClaims.get("sub"),
                "Subject should match for token " + i);
            assertEquals(i, validatedClaims.get("index"),
                "Index should match for token " + i);
        }
    }

    @Test
    @DisplayName("알고리즘 식별자 테스트")
    public void testAlgorithmIdentifier() {
        assertEquals("DILITHIUM3", Dilithium3Algorithm.getAlgorithmIdentifier(),
            "Algorithm identifier should be DILITHIUM3");
        assertTrue(Dilithium3Algorithm.isDilithium3("DILITHIUM3"),
            "Should recognize DILITHIUM3 identifier");
        assertFalse(Dilithium3Algorithm.isDilithium3("RS256"),
            "Should not recognize non-Dilithium3 identifier");
    }

    @Test
    @DisplayName("JWT Manager getter 메서드 테스트")
    public void testJwtManagerGetters() {
        assertEquals(keyPair.getPublic(), jwtManager.getPublicKey(),
            "Public key should match");
        assertEquals(keyPair.getPrivate(), jwtManager.getPrivateKey(),
            "Private key should match");
        assertEquals(Dilithium3Algorithm.DILITHIUM3, jwtManager.getAlgorithm(),
            "Algorithm should be DILITHIUM3");
    }

    @Test
    @DisplayName("빈 클레임으로 토큰 테스트")
    public void testTokenWithEmptyClaims() throws Exception {
        Map<String, Object> claims = new HashMap<>();

        String token = jwtManager.createToken(claims);
        assertNotNull(token, "Token should be created even with empty claims");

        Map<String, Object> validatedClaims = jwtManager.validateToken(token);
        assertNotNull(validatedClaims, "Validated claims should not be null");
        assertTrue(validatedClaims.containsKey("iat"),
            "Token should have auto-generated issued-at time");
    }

    @Test
    @DisplayName("Null 검증 테스트")
    public void testNullValidations() {
        // Test null token validation
        assertThrows(IllegalArgumentException.class, () -> {
            jwtManager.validateToken(null);
        }, "Should throw exception for null token");

        assertThrows(IllegalArgumentException.class, () -> {
            jwtManager.validateToken("");
        }, "Should throw exception for empty token");

        // Test null key pair
        assertThrows(IllegalArgumentException.class, () -> {
            new PQCJwtManager(null);
        }, "Should throw exception for null key pair");
    }
}
