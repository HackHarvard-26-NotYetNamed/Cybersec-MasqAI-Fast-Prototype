# ledger

A tiny double-entry ledger used by the back-office team. It reads `data/accounts.csv` and
`data/transactions.csv`, applies the transactions and prints the closing balances.

## Build and run (Windows)

```powershell
.\build.ps1
```

The build compiles `src/` with the JDK named by the `LEDGER_JDK` environment variable (or, on
developer machines, by the first line of an untracked `.ledger-jdk` file), packages
`out/ledger.jar` and runs it. The ops runbook requires the GUI launcher (`javaw.exe`) to be present in the
JDK, because the nightly job starts the ledger viewer with it.

Expected output:

```
Ledger OK: 3 accounts, 5 transactions, total balance 1250.00
```
