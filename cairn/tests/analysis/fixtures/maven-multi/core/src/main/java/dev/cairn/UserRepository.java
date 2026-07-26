package dev.cairn;

import java.sql.Statement;

public class UserRepository {
    public void find(String value, Statement statement) throws Exception {
        statement.execute("select * from users where name = " + value);
    }
}
