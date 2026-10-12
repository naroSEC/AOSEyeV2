package test;
import javax.crypto.spec.*;

public class CryptoParameterFixture {
    public static Object[] positive(char[] password, byte[] salt, byte[] iv) {
        return new Object[] {new PBEKeySpec(password, salt, 1),
            new PBEKeySpec(password, salt, 1, 128), new PBEParameterSpec(salt, 1),
            new GCMParameterSpec(32, iv), new GCMParameterSpec(64, iv, 0, iv.length)};
    }
    public static Object[] negative(char[] password, byte[] salt, byte[] iv, int unknown) {
        return new Object[] {new PBEKeySpec(password, salt, 600000, 128),
            new PBEKeySpec(password, salt, unknown), new GCMParameterSpec(128, iv),
            new GCMParameterSpec(unknown, iv)};
    }
}
