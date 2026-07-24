# Analysis of Next Generation Cryptography: Homomorphic Encryption

Coursework prototype and evaluation exploring **Homomorphic Encryption (HE)** — a cryptographic technique that allows computation to be performed directly on encrypted data, without ever decrypting it.

This repository contains a working prototype demonstrating a privacy-preserving computation use case, along with an evaluation suite benchmarking performance, accuracy, and parameter trade-offs.

---

## Overview

Homomorphic Encryption allows a party to process encrypted data and produce an encrypted result — which, when decrypted, matches the result of performing the same operation on the original plaintext data. This means computation can be outsourced to an untrusted party (e.g. a cloud server) without ever revealing the underlying data.

This project uses the **CKKS scheme** (Cheon-Kim-Kim-Song), which supports approximate arithmetic on real numbers, implemented via the **TenSEAL** library (built on Microsoft SEAL).

**Use case demonstrated:** Privacy-preserving average salary calculation — an HR system computes the average salary across multiple employees without any individual salary ever being visible in plaintext to the computing party.

---

## Repository Structure

```
├── salary_average.py          # Main prototype: encrypted average salary calculation
├── evaluation.py               # Evaluation suite: 3 benchmarking experiments
├── results_scaling.csv         # Results: timing vs number of encrypted values
├── results_scaling.png         # Chart: total processing time vs input size
├── results_parameters.csv      # Results: poly_modulus_degree trade-off comparison
├── results_depth.csv           # Results: accuracy degradation with multiplication depth
├── results_depth.png           # Chart: error growth with multiplicative depth
└── README.md                   # This file
```

---

## Requirements

- Python 3.8 – 3.12 (TenSEAL does not currently ship Windows wheels for 3.13+)
- Dependencies:
  ```bash
  pip install tenseal matplotlib
  ```

---

## How to Run

**1. Run the main prototype:**
```bash
python salary_average.py
```
Encrypts a set of sample salaries, computes their average entirely on encrypted data, decrypts the result, and validates it against the plaintext average.

**2. Run the evaluation suite:**
```bash
python evaluation.py
```
Runs three experiments and saves results as CSV files and PNG charts:
- **Scaling experiment** — measures encryption/computation/decryption time as the number of encrypted values increases (5 → 250)
- **Parameter trade-off experiment** — compares `poly_modulus_degree` settings (8192 / 16384 / 32768) across speed, ciphertext size, and accuracy
- **Multiplicative depth experiment** — repeatedly multiplies an encrypted value to show how error accumulates, and where the ciphertext eventually fails without bootstrapping

---

## GitHub Integrated References 

- **TenSEAL library**: OpenMined, *TenSEAL: A Library for Homomorphic Encryption Operations on Tensors*. https://github.com/OpenMined/TenSEAL
- Core encryption/decryption workflow adapted from TenSEAL's official tutorials (Tutorial 0 – Getting Started): https://github.com/OpenMined/TenSEAL/tree/main/tutorials
- Underlying HE library: Microsoft SEAL. https://github.com/microsoft/SEAL

---

MSc Cryptography Coursework — Edinburgh Napier University
