package com.acme.ledger;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Paths;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("usage: ledger <accounts.csv> <transactions.csv>");
            System.exit(2);
        }
        Ledger ledger = Ledger.load(Paths.get(args[0]));
        int applied = ledger.apply(Paths.get(args[1]));
        BigDecimal total = ledger.totalBalance();
        for (Account account : ledger.accounts()) {
            System.out.println(account);
        }
        System.out.printf("Ledger OK: %d accounts, %d transactions, total balance %s%n",
                ledger.accounts().size(), applied, total.toPlainString());
    }
}
