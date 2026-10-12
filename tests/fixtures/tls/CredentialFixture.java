package test;
import android.accounts.*;
import android.content.*;
import android.database.sqlite.SQLiteStatement;
import android.util.Log;
import java.io.*;

public class CredentialFixture {
    public static void positive(AccountManager manager, Account account, SharedPreferences.Editor editor,
            SQLiteStatement statement, Writer writer, FileOutputStream stream, ClipboardManager clipboard) throws Exception {
        String token = manager.peekAuthToken(account, "type");
        Log.d("tag", token);
        Log.println(4, "tag", token);
        editor.putString("token", token);
        editor.apply();
        statement.bindString(1, token);
        writer.write(token);
        stream.write(token.getBytes("UTF-8"));
        clipboard.setPrimaryClip(ClipData.newPlainText("label", token));
        helper(token);
    }
    private static void helper(String token) { Log.i("tag", token); }
    public static void negative(AccountManager manager, Account account, SharedPreferences.Editor editor,
            ClipboardManager clipboard) {
        String token = manager.peekAuthToken(account, "type");
        Log.d(token, "public message");
        editor.putString(token, "public value");
        clipboard.setPrimaryClip(ClipData.newPlainText(token, "public text"));
        token = "public";
        Log.i("tag", token);
    }
}
