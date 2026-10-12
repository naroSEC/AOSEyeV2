package test;
import android.app.*;
import android.content.*;
import android.os.*;
import android.webkit.WebView;
public class ComponentDeliveryFixture {
    public static void send(Context context, Intent incoming) {
        String url = incoming.getStringExtra("url");
        Intent service = new Intent(context, SinkService.class);
        service.putExtra("url", url);
        context.startService(service);
        Intent receiver = new Intent(context, SinkReceiver.class);
        receiver.putExtra("url", url);
        context.sendBroadcast(receiver);
        new Handler().post(new IntentTask(receiver));
    }
    public static class IntentTask implements Runnable {
        private final Intent captured;
        public IntentTask(Intent captured) { this.captured = captured; }
        public void run() { new WebView(null).loadUrl(captured.getStringExtra("url")); }
    }
    public static void named(Context context, Intent incoming) {
        String url = incoming.getStringExtra("url");
        Intent target = new Intent();
        target.setClassName("test.tls", "test.ComponentDeliveryFixture$SinkService");
        target.putExtra("url", url);
        context.startService(target);
    }
    public static void otherPackage(Context context, Intent incoming) {
        String url = incoming.getStringExtra("url");
        Intent target = new Intent();
        target.setClassName("other.package", "test.ComponentDeliveryFixture$SinkService");
        target.putExtra("url", url);
        context.startService(target);
    }
    public static class SinkService extends Service {
        public IBinder onBind(Intent intent) { return null; }
        public int onStartCommand(Intent intent, int flags, int id) {
            String url = intent.getStringExtra("url");
            new WebView(this).loadUrl(url);
            return 2;
        }
    }
    public static class SinkReceiver extends BroadcastReceiver {
        public void onReceive(Context context, Intent intent) {
            new WebView(context).loadUrl(intent.getStringExtra("url"));
        }
    }
}
