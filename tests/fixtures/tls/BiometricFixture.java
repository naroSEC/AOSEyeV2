package test;
import android.hardware.biometrics.BiometricPrompt;

public class BiometricFixture {
    public static class Forward extends BiometricPrompt.AuthenticationCallback {
        public void onAuthenticationFailed() { onAuthenticationSucceeded(null); }
        public void onAuthenticationError(int code, CharSequence text) { onAuthenticationSucceeded(null); }
        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
            // Deliberately no privileged action: the analyzer must remain REVIEW.
        }
    }
    public static class Reject extends BiometricPrompt.AuthenticationCallback {
        public void onAuthenticationFailed() {}
        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {}
    }
    public static class Unrelated {
        public void onAuthenticationFailed() { onAuthenticationSucceeded(null); }
        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {}
    }
}
