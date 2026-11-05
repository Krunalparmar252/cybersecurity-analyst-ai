# False Negative & Failure Analysis (Dev Repositories)
Analysis of missed ground truth labels on DEV split repositories (PyGoat, NodeGoat).
Per protocol rules, rule fixes may ONLY be motivated by dev repositories.

| Repo | Label ID | Class | Rule ID | Location | Failure Cause | Suggested Fix |
|---|---|---|---|---|---|---|
| nodegoat | `GT-NODEGOAT-SQLI-01` | SQL Injection | `SQLI-001` | `app/data/allocations-dao.js:78` | Framework pattern / AST structure mismatch | Refine AST selector or add framework handler pattern |
| nodegoat | `GT-NODEGOAT-CRYPTO-01` | Insecure Cryptography | `CRYPTO-003` | `app/data/user-dao.js:51` | Framework pattern / AST structure mismatch | Refine AST selector or add framework handler pattern |

## Top False Positive Causes
1. **Duplicate Rule Firing on Identical Line:** Multiple rules in the same family (e.g. `AUTH-001` and `AUTH-002`) firing on line 41 of user authentication check.
2. **Multiple Query Executions in Loop:** Safe query definitions inside helper functions or repeated calls on the same variable.
3. **Missing Context in Standalone Scripts:** Dev utility scripts lacking complete framework call graphs.
