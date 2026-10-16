package com.acme.ledger;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Ledger {
    private final Map<String, Account> accounts = new LinkedHashMap<>();

    public static Ledger load(Path csv) throws IOException {
        Ledger ledger = new Ledger();
        for (String[] row : rows(csv)) {
            ledger.accounts.put(row[0], new Account(row[0], row[1], new BigDecimal(row[2])));
        }
        return ledger;
    }

    /** Applies "from,to,amount" transfers and returns how many were applied. */
    public int apply(Path csv) throws IOException {
        int count = 0;
        for (String[] row : rows(csv)) {
            Account from = require(row[0]);
            Account to = require(row[1]);
            BigDecimal amount = new BigDecimal(row[2]);
            from.post(amount.negate());
            to.post(amount);
            count++;
        }
        return count;
    }

    public List<Account> accounts() {
        return new ArrayList<>(accounts.values());
    }

    public BigDecimal totalBalance() {
        BigDecimal total = BigDecimal.ZERO;
        for (Account account : accounts.values()) {
            total = total.add(account.balance());
        }
        return total;
    }

    private Account require(String id) {
        Account account = accounts.get(id);
        if (account == null) {
            throw new IllegalArgumentException("unknown account " + id);
        }
        return account;
    }

    private static List<String[]> rows(Path csv) throws IOException {
        List<String[]> rows = new ArrayList<>();
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (!line.isEmpty()) {
                rows.add(line.split(","));
            }
        }
        return rows;
    }
}
