package test;
import android.content.Intent;
import android.webkit.WebView;
public class WebReceiverFixture {
    public static void enabled(WebView view, Intent incoming) {
        String url = incoming.getDataString();
        view.getSettings().setJavaScriptEnabled(true);
        view.loadUrl(url);
    }
    public static void disabled(WebView view, Intent incoming) {
        String url = incoming.getDataString();
        view.getSettings().setJavaScriptEnabled(false);
        view.loadUrl(url);
    }
    public static void other(WebView first, WebView second, Intent incoming) {
        String url = incoming.getDataString();
        first.getSettings().setJavaScriptEnabled(true);
        second.loadUrl(url);
    }
    public static void bridge(WebView view, Object bridge, Intent incoming) {
        String url = incoming.getDataString();
        view.getSettings().setJavaScriptEnabled(true);
        view.addJavascriptInterface(bridge, "bridge");
        view.loadUrl(url);
    }
    public static void removedBridge(WebView view, Object bridge, Intent incoming) {
        String url = incoming.getDataString();
        view.addJavascriptInterface(bridge, "bridge");
        view.removeJavascriptInterface("bridge");
        view.loadUrl(url);
    }
}
