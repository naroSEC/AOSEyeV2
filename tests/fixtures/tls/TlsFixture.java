package test;

import javax.net.ssl.*;
import java.security.cert.*;
import android.webkit.*;
import android.net.http.SslError;

public class TlsFixture {
    public static void installMultiple(SSLContext context) throws Exception {
        context.init(null, new TrustManager[] {new RejectTrust(), new AcceptTrust()}, null);
    }
    public static void installTrust(SSLContext context) throws Exception {
        context.init(null, new TrustManager[] {new AcceptTrust()}, null);
    }
    public static void installSafeTrust(SSLContext context) throws Exception {
        context.init(null, new TrustManager[] {new RejectTrust()}, null);
    }
    public static void installHost(HttpsURLConnection connection) {
        connection.setHostnameVerifier(new AcceptHost());
    }
    public static void installDefault() {
        HttpsURLConnection.setDefaultHostnameVerifier(new AcceptHost());
    }
    public static void installClient(WebView view) {
        view.setWebViewClient(new ProceedClient());
    }
    public static void installReject(HttpsURLConnection connection) {
        connection.setHostnameVerifier(new RejectHost());
    }
    public static class AcceptTrust implements X509TrustManager {
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
    public static class RejectTrust implements X509TrustManager {
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException();
        }
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException();
        }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
    public static class AcceptHost implements HostnameVerifier {
        public boolean verify(String host, SSLSession session) { return true; }
    }
    public static class RejectHost implements HostnameVerifier {
        public boolean verify(String host, SSLSession session) { return false; }
    }
    public static class ProceedClient extends WebViewClient {
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) { handler.proceed(); }
    }
    public static class CancelClient extends WebViewClient {
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) { handler.cancel(); }
    }
}
