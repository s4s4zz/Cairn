package org.cairn.fixture;

public final class PlatformSql {
    public String queryForText(String statement) {
        return "synthetic-result:" + statement.length();
    }
}
