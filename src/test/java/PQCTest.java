import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public class PQCTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    @Test
    public void testKyber() throws Exception {
        // Kyber 키 쌍 생성
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber1024);
        KeyPair kp = kpg.generateKeyPair();

        // 래핑할 비밀 키 시뮬레이션
        byte[] secretKeyBytes = "secretkey1234567890123456".getBytes(); // 256-bit 키
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");

        // 키 래핑
        Cipher cipher = Cipher.getInstance("Kyber", "BCPQC");
        cipher.init(Cipher.WRAP_MODE, kp.getPublic());
        byte[] wrappedKey = cipher.wrap(secretKey);

        // 키 언래핑
        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        SecretKey recoveredKey = (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

        // 키가 일치하는지 검증
        assertArrayEquals(secretKey.getEncoded(), recoveredKey.getEncoded());
    }

    @Test
    public void testDilithium() throws Exception {
        // Dilithium 키 쌍 생성
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(DilithiumParameterSpec.dilithium5);
        KeyPair kp = kpg.generateKeyPair();

        // 서명할 메시지
        byte[] message = "Hello, PQC!".getBytes();

        // 메시지 서명
        Signature sig = Signature.getInstance("Dilithium", "BCPQC");
        sig.initSign(kp.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        // 서명 검증
        sig.initVerify(kp.getPublic());
        sig.update(message);
        boolean verified = sig.verify(signature);

        assertTrue(verified);
    }

    @Test
    public void testDilithium3() throws Exception {
        // Dilithium3 키 쌍 생성
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(DilithiumParameterSpec.dilithium3);
        KeyPair kp = kpg.generateKeyPair();

        // 서명할 메시지
        byte[] message = "Testing Dilithium3 signature algorithm".getBytes();

        // 메시지 서명
        Signature sig = Signature.getInstance("Dilithium", "BCPQC");
        sig.initSign(kp.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        // 서명 검증
        sig.initVerify(kp.getPublic());
        sig.update(message);
        boolean verified = sig.verify(signature);

        assertTrue(verified, "Dilithium3 signature verification should succeed");

        // 변조된 메시지로 테스트 (실패해야 함)
        byte[] modifiedMessage = "Modified message".getBytes();
        sig.initVerify(kp.getPublic());
        sig.update(modifiedMessage);
        boolean verifiedModified = sig.verify(signature);

        assertFalse(verifiedModified, "Dilithium3 signature verification should fail for modified message");
    }
}