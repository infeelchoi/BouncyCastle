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
        // Generate Kyber key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber1024);
        KeyPair kp = kpg.generateKeyPair();

        // Simulate a secret key to wrap
        byte[] secretKeyBytes = "secretkey1234567890123456".getBytes(); // 256-bit key
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");

        // Wrap the key
        Cipher cipher = Cipher.getInstance("Kyber", "BCPQC");
        cipher.init(Cipher.WRAP_MODE, kp.getPublic());
        byte[] wrappedKey = cipher.wrap(secretKey);

        // Unwrap the key
        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        SecretKey recoveredKey = (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

        // Verify the keys match
        assertArrayEquals(secretKey.getEncoded(), recoveredKey.getEncoded());
    }

    @Test
    public void testDilithium() throws Exception {
        // Generate Dilithium key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(DilithiumParameterSpec.dilithium5);
        KeyPair kp = kpg.generateKeyPair();

        // Message to sign
        byte[] message = "Hello, PQC!".getBytes();

        // Sign the message
        Signature sig = Signature.getInstance("Dilithium", "BCPQC");
        sig.initSign(kp.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        // Verify the signature
        sig.initVerify(kp.getPublic());
        sig.update(message);
        boolean verified = sig.verify(signature);

        assertTrue(verified);
    }
}