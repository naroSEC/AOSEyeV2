package test;
import android.app.Activity;
import android.webkit.WebView;
// Compilation stubs and fixture only. Never install or execute as an Android app.
public class Main extends Activity {
    public void onCreate(android.os.Bundle savedInstanceState) {
        Navigation.open(getIntent().getStringExtra("url"));
    }
    public void safe() {
        String value = getIntent().getStringExtra("url");
        value = "https://safe.example/";
        Navigation.open(value);
    }
}
class Navigation {
    public static String last;
    public static String peek() { return last; }
    public static void open(String value) { last = value; new WebView().loadUrl(value); }
    public static void conditional(String value, boolean allow) {
        if (allow) { new WebView().loadUrl(value); }
    }
    public static void rangeCall(String value) { accept(1, 2, 3, 4, 5, value); }
    public static void accept(int a, int b, int c, int d, int e, String value) {
        new WebView().loadUrl(value);
    }
}
