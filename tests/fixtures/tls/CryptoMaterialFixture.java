package test;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.*;

public class CryptoMaterialFixture {
    public static void base64Positive(Cipher cipher) throws Exception {
        byte[] bytes = android.util.Base64.decode("MDEyMzQ1Njc4OWFiY2RlZg==", 0);
        cipher.init(1, new SecretKeySpec(bytes, "AES"));
    }
    public static void positive(Cipher cipher) throws Exception {
        SecretKeySpec key = new SecretKeySpec("fixture-key-only".getBytes("UTF-8"), "AES");
        IvParameterSpec iv = new IvParameterSpec("fixture-iv-only!".getBytes("UTF-8"));
        cipher.init(1, key, iv);
    }
    public static void negative(Cipher cipher, byte[] keyBytes, byte[] ivBytes) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(1, key, iv);
    }
    public static void saltPositive(SecretKeyFactory factory, char[] password) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, "fixture-salt-only".getBytes("UTF-8"), 600000, 128);
        factory.generateSecret(spec);
    }
    public static void saltNegative(SecretKeyFactory factory, char[] password, byte[] salt) throws Exception {
        factory.generateSecret(new PBEKeySpec(password, salt, 600000, 128));
    }
}
