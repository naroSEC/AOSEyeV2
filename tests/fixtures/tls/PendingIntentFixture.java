package test;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

public class PendingIntentFixture {
    public static PendingIntent implicit(Context context) {
        return PendingIntent.getActivity(context, 0, new Intent("test.ACTION"), PendingIntent.FLAG_MUTABLE);
    }
    public static PendingIntent conflict(Context context) {
        return PendingIntent.getBroadcast(context, 0, new Intent(), PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_IMMUTABLE);
    }
    public static PendingIntent explicit(Context context) {
        return PendingIntent.getActivity(context, 0, new Intent(context, PendingIntentFixture.class), PendingIntent.FLAG_MUTABLE);
    }
    public static PendingIntent restricted(Context context) {
        return PendingIntent.getBroadcast(context, 0, new Intent("test.ACTION").setPackage("test.package"), PendingIntent.FLAG_MUTABLE);
    }
    public static PendingIntent immutable(Context context) {
        return PendingIntent.getService(context, 0, new Intent(), PendingIntent.FLAG_IMMUTABLE);
    }
    public static PendingIntent cleared(Context context) {
        Intent intent = new Intent().setClass(context, PendingIntentFixture.class);
        intent.setComponent(null);
        return PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_MUTABLE);
    }
    public static PendingIntent copyUnrestricted(Context context) {
        Intent original = new Intent();
        Intent copy = new Intent(original);
        original.setClassName(context, "test.Target");
        return PendingIntent.getActivity(context, 0, copy, PendingIntent.FLAG_MUTABLE);
    }
    public static PendingIntent copyRestricted(Context context) {
        Intent original = new Intent().setClassName("test.package", "test.Target");
        Intent copy = new Intent(original);
        original.setComponent(null);
        return PendingIntent.getActivity(context, 0, copy, PendingIntent.FLAG_MUTABLE);
    }
}
