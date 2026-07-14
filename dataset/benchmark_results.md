# Benchmark Results

- Total samples: **317**
- Vulnerable: 288 | Secure: 29
- **Overall recall: 1.0** (target ≥ 0.85)
- Overall precision: 1.0
- Overall F1: 1.0

## Per-type

| Type | TP | FN | FP | TN | Precision | Recall | F1 |
|------|----|----|----|----|----------|-------|----|
| command_injection | 72 | 0 | 0 | 5 | 1.0 | 1.0 | 1.0 |
| hardcoded_secret | 72 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 |
| sql_injection | 72 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 |
| xss | 72 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 |
