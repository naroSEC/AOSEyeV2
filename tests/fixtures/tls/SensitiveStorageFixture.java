package test;
import android.accounts.*;
import android.content.Context;
import android.database.sqlite.SQLiteStatement;
import java.io.FileOutputStream;

public class SensitiveStorageFixture {
    public static void sql(AccountManager manager, Account account, SQLiteStatement statement) {
        String token = manager.peekAuthToken(account, "type");
        statement.bindString(1, token);
        statement.executeInsert();
    }
    public static void cleared(AccountManager manager, Account account, SQLiteStatement statement) {
        String token = manager.peekAuthToken(account, "type");
        statement.bindString(1, token);
        statement.clearBindings();
        statement.executeInsert();
    }
    public static void file(AccountManager manager, Account account, Context context) throws Exception {
        String token = manager.peekAuthToken(account, "type");
        FileOutputStream stream = context.openFileOutput("fixture-credential", 0);
        stream.write(token.getBytes());
    }
    public static void otherFile(AccountManager manager, Account account, Context context,
                                 FileOutputStream other) throws Exception {
        String token = manager.peekAuthToken(account, "type");
        FileOutputStream stream = context.openFileOutput("fixture-credential", 0);
        other.write(token.getBytes());
    }
}
