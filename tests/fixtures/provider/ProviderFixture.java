package test;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.webkit.WebView;

// Static-analysis fixture only. Never installed or executed.
public class ProviderFixture extends ContentProvider {
    private static int arraySize(Object[] value) { return value.length; }
    private static int lastIndex(Object[] value) { return value.length - 1; }
    private static int tripleSize(Object[] value) { return value.length * 3; }
    public boolean onCreate() { return true; }
    public String getType(Uri uri) { return null; }
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        String[] values = new String[2];
        values[0] = selection;
        String[] copied = new String[2];
        System.arraycopy(values, 0, copied, 0, 1);
        java.util.ArrayList<String> source = new java.util.ArrayList<String>(4);
        source.add(copied[0]);
        java.util.List<String> joined = new java.util.ArrayList<String>();
        joined.add("safe-prefix");
        joined.addAll(0, source);
        java.util.ArrayList<String> result = new java.util.ArrayList<String>();
        java.util.Collection<String> target = result;
        target.addAll(joined);
        java.util.ArrayList<String> independent = new java.util.ArrayList<String>(result);
        result.clear();
        result = independent;
        java.util.ArrayList<String> clonedList = (java.util.ArrayList<String>) result.clone();
        result.clear();
        result = clonedList;
        source.clear();
        joined.clear();
        // Constant size result selects a safe appended slot. The conditional is
        // deliberately absent: this tests value propagation, not branch solving.
        int end = result.size();
        result.isEmpty();
        result.add("safe-at-old-size");
        new WebView(getContext()).loadUrl(result.get(end));
        new WebView(getContext()).loadUrl(result.get(0));
        new WebView(getContext()).loadUrl(result.get(1)); // Safe copied slot, no flow.
        java.util.Collections.swap(result, 0, 1);
        new WebView(getContext()).loadUrl(result.get(0)); // Now safe, no flow.
        new WebView(getContext()).loadUrl(result.get(1)); // Moved input.
        java.util.Collections.swap(result, 0, 1); // Restore for iterator regression.
        java.util.Collections.reverse(result);
        new WebView(getContext()).loadUrl(result.get(0)); // Reversed safe tail.
        new WebView(getContext()).loadUrl(result.get(2)); // Input moved from index 0.
        java.util.Collections.reverse(result); // Restore for iterator regression.
        java.util.Collections.rotate(result, 4); // Size 3: input moves 0 -> 1.
        new WebView(getContext()).loadUrl(result.get(0)); // Safe tail.
        new WebView(getContext()).loadUrl(result.get(1));
        java.util.Collections.rotate(result, -4); // Input returns to index 0.
        String fillValue = result.get(0);
        java.lang.Iterable<String> iterable = result;
        java.util.Iterator<String> iterator = iterable.iterator();
        iterator.hasNext();
        new WebView(getContext()).loadUrl(iterator.next());
        iterator.remove();
        new WebView(getContext()).loadUrl(result.get(0)); // Removed input, now safe.
        new WebView(getContext()).loadUrl(iterator.next()); // Safe second slot.
        java.util.Collections.fill(result, fillValue);
        new WebView(getContext()).loadUrl(result.get(1)); // Previously safe, now input.
        java.util.Collections.fill(result, "safe-fill");
        new WebView(getContext()).loadUrl(result.get(0));
        new WebView(getContext()).loadUrl(result.get(1));
        java.util.Collections.fill(result, fillValue);
        java.util.Collections.fill(result, null);
        new WebView(getContext()).loadUrl(result.get(0));
        source.add(fillValue);
        java.util.Collections.copy(result, source);
        source.clear(); // Destination retains copied input independently.
        new WebView(getContext()).loadUrl(result.get(0));
        new WebView(getContext()).loadUrl(result.get(1)); // Untouched null tail.
        source.add("safe-copy");
        java.util.Collections.copy(result, source);
        new WebView(getContext()).loadUrl(result.get(0));
        String[] additions = new String[] { fillValue, "safe-added" };
        java.util.Collections.addAll(result, additions);
        additions[0] = "safe-array-overwrite";
        java.util.Collections.addAll(result, new String[0]);
        new WebView(getContext()).loadUrl(result.get(2)); // Copied input survives array change.
        new WebView(getContext()).loadUrl(result.get(3)); // Safe appended slot.
        new WebView(getContext()).loadUrl(result.get(0)); // Safe prefix retained.
        Object[] filled = new Object[tripleSize(new Object[1])];
        java.util.Arrays.fill(filled, fillValue);
        new WebView(getContext()).loadUrl((String) filled[lastIndex(filled)]);
        new WebView(getContext()).loadUrl((String) filled[arraySize(filled) - 1]);
        java.util.Arrays.fill(filled, "safe-fill-array");
        new WebView(getContext()).loadUrl((String) filled[0]);
        java.util.Arrays.fill(filled, fillValue);
        java.util.Arrays.fill(filled, null);
        new WebView(getContext()).loadUrl((String) filled[1]);
        java.util.Arrays.fill(filled, 0, 1, fillValue);
        new WebView(getContext()).loadUrl((String) filled[0]);
        new WebView(getContext()).loadUrl((String) filled[1]); // Exclusive endpoint remains null.
        java.util.Arrays.fill(filled, 1, arraySize(filled), "safe-tail");
        java.util.Arrays.fill(filled, 0, 0, "empty-range");
        new WebView(getContext()).loadUrl((String) filled[0]); // Outside range preserved.
        java.util.Arrays.fill(filled, 0, 1, null);
        new WebView(getContext()).loadUrl((String) filled[0]);
        Object[] uncertainWrites = new Object[2];
        uncertainWrites[selection.length() % 2] = fillValue;
        System.arraycopy(new Object[1], 0, uncertainWrites, 0, 1);
        new WebView(getContext()).loadUrl((String) uncertainWrites[0]); // Overwritten wildcard must not leak.
        System.arraycopy(new Object[2], 0, uncertainWrites, 0, 2);
        new WebView(getContext()).loadUrl((String) uncertainWrites[1]); // Full overwrite clears remaining input.
        uncertainWrites[selection.length() % 2] = fillValue;
        uncertainWrites[0] = "safe-known-store";
        new WebView(getContext()).loadUrl((String) uncertainWrites[0]);
        uncertainWrites[1] = null;
        new WebView(getContext()).loadUrl((String) uncertainWrites[1]);
        result.clear();
        result.add("safe-after-clear");
        new WebView(getContext()).loadUrl(result.get(0));
        return null;
    }
    public Uri insert(Uri uri, ContentValues values) { return null; }
    public int update(Uri uri, ContentValues values, String selection, String[] args) {
        String[] initial = new String[] { selection, "safe" };
        String[] cloned = initial.clone();
        initial[0] = "safe-after-clone";
        String[] resized = java.util.Arrays.copyOf(cloned, 3);
        java.util.Map<String, String> map = new java.util.HashMap<String, String>(4);
        map.put("url", resized[0]);
        java.util.HashMap<String, String> sourceMap = new java.util.HashMap<String, String>(map);
        java.util.HashMap<String, String> clonedMap = (java.util.HashMap<String, String>) sourceMap.clone();
        sourceMap.clear();
        sourceMap = clonedMap;
        map.clear();
        map.putAll(sourceMap);
        sourceMap.clear();
        map.containsKey("url");
        map.size();
        map.isEmpty();
        new WebView(getContext()).loadUrl(map.get("url"));
        new WebView(getContext()).loadUrl(map.replace("url", "safe-replaced"));
        new WebView(getContext()).loadUrl(map.get("url"));
        map.replace("absent", resized[0]);
        new WebView(getContext()).loadUrl(map.get("absent"));
        map.put("url", resized[0]); // Keep the putAll overwrite regression independent.
        sourceMap.put("url", "safe");
        map.putAll(sourceMap);
        new WebView(getContext()).loadUrl(map.getOrDefault("url", resized[0])); // Present safe mapping wins.
        map.put("nullable", null);
        new WebView(getContext()).loadUrl(map.getOrDefault("nullable", resized[0])); // Present null also wins.
        new WebView(getContext()).loadUrl(map.get("url"));
        map.put("url", resized[0]);
        map.remove("url");
        new WebView(getContext()).loadUrl(map.get("url"));
        map.put("url", resized[0]);
        map.clear();
        new WebView(getContext()).loadUrl(map.getOrDefault("absent", resized[0]));
        new WebView(getContext()).loadUrl(map.get("url"));
        new WebView(getContext()).loadUrl(resized[2]); // Padded null: no input flow.
        return 0;
    }
    public int delete(Uri uri, String selection, String[] args) { return 0; }
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        String[] initial = new String[] { mode, "safe" };
        java.util.ArrayList<String> items = new java.util.ArrayList<String>();
        items.add(initial[0]);
        items.add(0, "safe-prefix");
        items.remove(0);
        new WebView(getContext()).loadUrl(items.get(0));
        Object[] snapshot = items.toArray();
        items.set(0, "safe");
        new WebView(getContext()).loadUrl((String) snapshot[0]);
        snapshot[0] = "safe-array";
        new WebView(getContext()).loadUrl((String) snapshot[0]);
        new WebView(getContext()).loadUrl(items.get(0));
        items.clear();
        items.add("safe-after-clear");
        new WebView(getContext()).loadUrl(items.get(0));
        return null;
    }
    public Bundle call(String method, String argument, Bundle extras) {
        String[] initial = new String[] { method, argument, "a", "b", "c", "d" };
        String[] sliced = java.util.Arrays.copyOfRange(initial, 1, 8);
        java.util.List<String> items = new java.util.ArrayList<String>();
        java.util.Collection<String> collection = items;
        collection.add(sliced[0]);
        Object[] snapshot = collection.toArray();
        snapshot[0] = "safe-array";
        new WebView(getContext()).loadUrl((String) snapshot[0]);
        Object[] destination = new Object[] { "old", argument, "safe-tail" };
        Object[] reused = collection.toArray(destination);
        new WebView(getContext()).loadUrl((String) destination[0]);
        new WebView(getContext()).loadUrl((String) reused[1]); // Null terminator, no flow.
        new WebView(getContext()).loadUrl((String) reused[2]); // Untouched safe tail.
        Object[] allocated = items.toArray(new Object[0]);
        new WebView(getContext()).loadUrl((String) allocated[0]);
        new WebView(getContext()).loadUrl(items.get(0));
        new WebView(getContext()).loadUrl(items.remove(0));
        items.add("safe-replacement");
        items.set(0, "safe");
        new WebView(getContext()).loadUrl(items.get(0));
        collection.clear();
        items.add("safe-after-clear");
        new WebView(getContext()).loadUrl(items.get(0));
        new WebView(getContext()).loadUrl(sliced[6]); // Padded null: no input flow.
        return null;
    }
}
