package android.net;
public abstract class Uri {
    public static Uri parse(String text) { return null; }
    public abstract String getScheme();
    public abstract String getHost();
}
