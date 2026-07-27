package dev.cairn.shop;

import java.sql.Statement;

public class OrderRepository {

    private final Statement statement;

    public OrderRepository(Statement statement) {
        this.statement = statement;
    }

    public String findByOwner(String owner) {
        try {
            statement.execute("select * from orders where owner = '" + owner + "'");
            return "ok";
        } catch (Exception failure) {
            return "error";
        }
    }
}
