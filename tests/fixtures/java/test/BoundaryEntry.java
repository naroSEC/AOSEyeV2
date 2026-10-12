package test;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.webkit.WebView;

// Static analysis fixture. Never install or execute as an Android app.
public class BoundaryEntry extends Activity {
    public void onCreate(Bundle state) {
        String url = getIntent().getStringExtra("url");
        new Handler().post(new BoundaryTask(url));
        Intent intent = new Intent(this, BoundaryDestination.class);
        intent.putExtra("url", url);
        startActivity(intent);
    }
}
class BoundaryTask implements Runnable {
    private final String value;
    BoundaryTask(String value) { this.value = value; }
    public void run() { new WebView().loadUrl(value); }
}
class BoundaryDestination extends Activity {
    public void onCreate(Bundle state) {
        new WebView().loadUrl(getIntent().getStringExtra("url"));
    }
}
