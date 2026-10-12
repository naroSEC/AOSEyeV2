package test;
import android.app.DownloadManager;
import dalvik.system.DexClassLoader;
import dalvik.system.PathClassLoader;

public class DownloadFixture {
    public static ClassLoader positive(DownloadManager manager, long id, ClassLoader parent) {
        return new DexClassLoader(manager.getUriForDownloadedFile(id).getPath(), null, null, parent);
    }
    public static ClassLoader helperPositive(DownloadManager manager, long id, ClassLoader parent) {
        return load(manager.getUriForDownloadedFile(id).toString(), parent);
    }
    private static ClassLoader load(String path, ClassLoader parent) {
        return new PathClassLoader(path, parent);
    }
    public static ClassLoader wrongArgument(DownloadManager manager, long id, ClassLoader parent) {
        return new DexClassLoader("fixed.apk", manager.getUriForDownloadedFile(id).getPath(), null, parent);
    }
    public static ClassLoader overwritten(DownloadManager manager, long id, ClassLoader parent) {
        String path = manager.getUriForDownloadedFile(id).getPath();
        path = "fixed.apk";
        return new PathClassLoader(path, parent);
    }
}
