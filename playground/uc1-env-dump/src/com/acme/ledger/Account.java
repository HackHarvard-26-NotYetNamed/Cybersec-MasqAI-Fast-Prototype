package com.acme.ledger;

import java.math.BigDecimal;

public final class Account {
    private final String id;
    private final String name;
    private BigDecimal balance;

    public Account(String id, String name, BigDecimal opening) {
        this.id = id;
        this.name = name;
        this.balance = opening;
    }

    public String id() {
        return id;
    }

    public BigDecimal balance() {
        return balance;
    }

    void post(BigDecimal amount) {
        balance = balance.add(amount);
    }

    @Override
    public String toString() {
        return String.format("%-6s %-14s %10s", id, name, balance.toPlainString());
    }
}
