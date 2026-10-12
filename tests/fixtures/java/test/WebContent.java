package test;
import android.content.Intent;
import android.webkit.WebView;

// Analysis fixture only: proves content and history arguments remain distinct.
public class WebContent {
    public static void html(Intent intent, WebView view) {
        view.loadDataWithBaseURL("https://safe.example/", intent.getStringExtra("html"),
                                "text/html", "UTF-8", null);
    }
    public static void historyOnly(Intent intent, WebView view) {
        view.loadDataWithBaseURL("https://safe.example/", "<p>constant</p>",
                                "text/html", "UTF-8", intent.getStringExtra("history"));
    }
    public static void script(Intent intent, WebView view) {
        view.evaluateJavascript(intent.getStringExtra("script"), null);
    }
}
