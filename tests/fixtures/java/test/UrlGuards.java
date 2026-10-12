package test;
import android.net.Uri;
import android.webkit.WebView;

public class UrlGuards {
    public static boolean allowed(String url) {
        Uri parsed = Uri.parse(url);
        if (!"https".equals(parsed.getScheme())) return false;
        return "trusted.example".equals(parsed.getHost());
    }
    public static void helper(WebView view, String url) {
        if (allowed(url)) view.loadUrl(url);
    }
    public static void helperOther(WebView view, String url, String other) {
        if (allowed(other)) view.loadUrl(url);
    }
    public static boolean failOpen(String url) {
        try { return allowed(url); }
        catch (RuntimeException ignored) { return true; }
    }
    public static boolean failClosed(String url) {
        try { return allowed(url); }
        catch (RuntimeException ignored) { return false; }
    }
    public static void helperCatchOpen(WebView view, String url) {
        if (failOpen(url)) view.loadUrl(url);
    }
    public static void helperCatchClosed(WebView view, String url) {
        if (failClosed(url)) view.loadUrl(url);
    }
    public static void callerCatch(WebView view, String url) {
        try { if (!allowed(url)) return; }
        catch (RuntimeException ignored) { }
        view.loadUrl(url);
    }
    public static void exact(WebView view, String url) {
        Uri parsed = Uri.parse(url);
        if (!"https".equals(parsed.getScheme())) return;
        if (!"trusted.example".equals(parsed.getHost())) return;
        view.loadUrl(url);
    }
    public static void prefix(WebView view, String url) {
        if (url.startsWith("https://trusted.example")) view.loadUrl(url);
    }
    public static void replaced(WebView view, String url, String other) {
        Uri parsed = Uri.parse(url);
        if (!"https".equals(parsed.getScheme())) return;
        if (!"trusted.example".equals(parsed.getHost())) return;
        url = other;
        view.loadUrl(url);
    }
}
