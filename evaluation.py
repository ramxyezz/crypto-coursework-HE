"""
Evaluation & Benchmarking of Homomorphic Encryption (TenSEAL/CKKS)
----------------------------------------------------------------------------
This script produces the empirical evidence for the coursework's
Evaluation section. It measures:

  1. How encryption/decryption/computation time scales with input size
     (i.e. number of encrypted values / vector length).
  2. How ciphertext size compares to plaintext size.
  3. How accuracy (error vs plaintext) behaves - since CKKS is approximate.
  4. How different poly_modulus_degree parameter choices affect
     performance vs precision (a classic HE security/speed trade-off).

Results are printed as tables and saved to CSV files + charts (PNG)
so they can be dropped straight into the report.
"""

import tenseal as ts
import time
import csv
import random
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_PLT = True
except ImportError:
    HAVE_PLT = False
    print("[warning] matplotlib not installed - will skip chart generation. "
          "Run: pip install matplotlib")


def make_context(poly_modulus_degree=8192, coeff_mod_bit_sizes=None):
    if coeff_mod_bit_sizes is None:
        coeff_mod_bit_sizes = [60, 40, 40, 60]
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=poly_modulus_degree,
        coeff_mod_bit_sizes=coeff_mod_bit_sizes
    )
    context.generate_galois_keys()
    context.global_scale = 2**40
    return context


# ---------------------------------------------------------------------
# Experiment 1: Scaling - how do timings change as dataset size grows?
# ---------------------------------------------------------------------
def experiment_scaling(sizes=(5, 10, 25, 50, 100, 250)):
    print("\n=== Experiment 1: Scaling with number of encrypted values ===")
    context = make_context()
    results = []

    for n in sizes:
        values = [random.uniform(30000, 70000) for _ in range(n)]

        t0 = time.time()
        encrypted = [ts.ckks_vector(context, [v]) for v in values]
        t_encrypt = time.time() - t0

        t0 = time.time()
        enc_sum = encrypted[0]
        for e in encrypted[1:]:
            enc_sum = enc_sum + e
        enc_avg = enc_sum * (1.0 / n)
        t_compute = time.time() - t0

        t0 = time.time()
        result = enc_avg.decrypt()[0]
        t_decrypt = time.time() - t0

        expected = sum(values) / n
        error = abs(result - expected)

        ct_size = len(encrypted[0].serialize())

        results.append({
            "n": n,
            "encrypt_ms": round(t_encrypt * 1000, 3),
            "compute_ms": round(t_compute * 1000, 3),
            "decrypt_ms": round(t_decrypt * 1000, 3),
            "total_ms": round((t_encrypt + t_compute + t_decrypt) * 1000, 3),
            "error": round(error, 6),
            "ciphertext_bytes": ct_size,
            "plaintext_bytes": sys.getsizeof(values[0]),
        })

        print(f"n={n:>4} | encrypt={t_encrypt*1000:7.2f}ms | "
              f"compute={t_compute*1000:6.2f}ms | decrypt={t_decrypt*1000:6.2f}ms | "
              f"error={error:.6f} | ciphertext={ct_size} bytes")

    return results


# ---------------------------------------------------------------------
# Experiment 2: Parameter trade-off - poly_modulus_degree vs speed
# ---------------------------------------------------------------------
def experiment_parameters(degrees=(8192, 16384, 32768)):
    print("\n=== Experiment 2: poly_modulus_degree trade-off (security vs speed) ===")
    results = []
    values = [random.uniform(30000, 70000) for _ in range(20)]

    for degree in degrees:
        if degree == 8192:
            coeff_sizes = [60, 40, 40, 60]
        elif degree == 16384:
            coeff_sizes = [60, 40, 40, 40, 40, 60]
        else:  # 32768
            coeff_sizes = [60, 40, 40, 40, 40, 40, 40, 60]

        try:
            context = make_context(poly_modulus_degree=degree, coeff_mod_bit_sizes=coeff_sizes)

            t0 = time.time()
            encrypted = [ts.ckks_vector(context, [v]) for v in values]
            t_encrypt = time.time() - t0

            t0 = time.time()
            enc_sum = encrypted[0]
            for e in encrypted[1:]:
                enc_sum = enc_sum + e
            enc_avg = enc_sum * (1.0 / len(values))
            t_compute = time.time() - t0

            result = enc_avg.decrypt()[0]
            expected = sum(values) / len(values)
            error = abs(result - expected)
            ct_size = len(encrypted[0].serialize())

            results.append({
                "poly_modulus_degree": degree,
                "encrypt_ms": round(t_encrypt * 1000, 3),
                "compute_ms": round(t_compute * 1000, 3),
                "error": round(error, 6),
                "ciphertext_bytes": ct_size,
            })

            print(f"degree={degree:>6} | encrypt={t_encrypt*1000:7.2f}ms | "
                  f"compute={t_compute*1000:6.2f}ms | error={error:.6f} | "
                  f"ciphertext={ct_size} bytes")

        except Exception as ex:
            print(f"degree={degree:>6} | FAILED: {ex}")

    return results


# ---------------------------------------------------------------------
# Experiment 3: Noise budget / repeated multiplication depth
# ---------------------------------------------------------------------
def experiment_multiplicative_depth(max_multiplications=5):
    print("\n=== Experiment 3: Accuracy degradation with multiplicative depth ===")
    context = make_context(poly_modulus_degree=16384,
                            coeff_mod_bit_sizes=[60, 40, 40, 40, 40, 60])
    results = []

    value = 1.5
    enc = ts.ckks_vector(context, [value])
    plaintext_value = value

    for depth in range(1, max_multiplications + 1):
        try:
            enc = enc * 1.5
            plaintext_value *= 1.5
            decrypted = enc.decrypt()[0]
            error = abs(decrypted - plaintext_value)
            results.append({
                "depth": depth,
                "decrypted": round(decrypted, 6),
                "expected": round(plaintext_value, 6),
                "error": round(error, 8),
            })
            print(f"depth={depth} | decrypted={decrypted:.6f} | "
                  f"expected={plaintext_value:.6f} | error={error:.8f}")
        except Exception as ex:
            print(f"depth={depth} | FAILED (ciphertext exhausted): {ex}")
            break

    return results


def save_csv(results, filename):
    if not results:
        return
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"Saved: {filename}")


def plot_scaling(results):
    if not HAVE_PLT or not results:
        return
    ns = [r["n"] for r in results]
    total = [r["total_ms"] for r in results]

    plt.figure(figsize=(7, 5))
    plt.plot(ns, total, marker="o")
    plt.xlabel("Number of encrypted values (n)")
    plt.ylabel("Total time (ms)")
    plt.title("HE Total Processing Time vs Input Size (TenSEAL / CKKS)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("results_scaling.png", dpi=150)
    print("Saved: results_scaling.png")


def plot_depth(results):
    if not HAVE_PLT or not results:
        return
    depths = [r["depth"] for r in results]
    errors = [r["error"] for r in results]

    plt.figure(figsize=(7, 5))
    plt.plot(depths, errors, marker="o", color="crimson")
    plt.xlabel("Multiplicative depth")
    plt.ylabel("Absolute error vs plaintext")
    plt.title("Error Growth with Multiplicative Depth (CKKS)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("results_depth.png", dpi=150)
    print("Saved: results_depth.png")


if __name__ == "__main__":
    scaling_results = experiment_scaling()
    save_csv(scaling_results, "results_scaling.csv")
    plot_scaling(scaling_results)

    param_results = experiment_parameters()
    save_csv(param_results, "results_parameters.csv")

    depth_results = experiment_multiplicative_depth()
    save_csv(depth_results, "results_depth.csv")
    plot_depth(depth_results)

    print("\nAll experiments complete. CSVs and charts saved to current directory.")
