package test;
import java.security.*;
public class SignatureResultFixture {
    public static boolean ignored(Signature signature, byte[] bytes) throws Exception {
        signature.verify(bytes);
        return true;
    }
    public static boolean used(Signature signature, byte[] bytes) throws Exception {
        return signature.verify(bytes);
    }
    public static boolean reject(Signature signature, byte[] bytes) throws Exception {
        signature.verify(bytes);
        return false;
    }
}
