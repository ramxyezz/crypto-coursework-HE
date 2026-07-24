"""
Privacy-Preserving Average Salary Calculation
--------------------------------------------------------
Use case: An HR system wants to compute the AVERAGE salary across several
employees WITHOUT ever seeing individual salary values in plaintext.

Each employee's salary is encrypted on their own machine (simulated here).
The "server" only ever operates on ciphertexts. Only the party holding the
secret key (e.g. an auditor) can decrypt the final average.

Library: TenSEAL (https://github.com/OpenMined/TenSEAL)
Scheme: CKKS (approximate arithmetic on real numbers)
"""

import tenseal as ts
import time

# -------------------------------------------------------------------
# 1. Setup: create HE context (this would normally happen once,
#    and the secret key would stay ONLY with the trusted party)
# -------------------------------------------------------------------
def create_context():
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    context.generate_galois_keys()
    context.global_scale = 2**40
    return context

# -------------------------------------------------------------------
# 2. Simulate multiple employees encrypting their own salary
#    (in a real system, each employee would do this locally,
#    with only the PUBLIC key, before sending it to the server)
# -------------------------------------------------------------------
def encrypt_salaries(context, salaries):
    encrypted_salaries = []
    for salary in salaries:
        enc = ts.ckks_vector(context, [salary])
        encrypted_salaries.append(enc)
    return encrypted_salaries

# -------------------------------------------------------------------
# 3. Server-side computation: sum all encrypted salaries and divide
#    by count. The server NEVER sees plaintext salary values.
# -------------------------------------------------------------------
def compute_encrypted_average(encrypted_salaries):
    encrypted_sum = encrypted_salaries[0]
    for enc_salary in encrypted_salaries[1:]:
        encrypted_sum = encrypted_sum + enc_salary

    # Division by a known public constant (count) is allowed:
    # HE supports plaintext-ciphertext multiplication, so we multiply
    # by (1/count) rather than performing ciphertext division.
    count = len(encrypted_salaries)
    encrypted_average = encrypted_sum * (1.0 / count)
    return encrypted_average

# -------------------------------------------------------------------
# 4. Run the demo
# -------------------------------------------------------------------
def main():
    salaries = [42000, 51000, 39500, 60250, 47800]  # kept private in a real system
    print(f"Number of employees: {len(salaries)}")
    print("(Individual salaries are hidden from the server in a real deployment)\n")

    context = create_context()

    start = time.time()
    encrypted_salaries = encrypt_salaries(context, salaries)
    encrypt_time = time.time() - start

    start = time.time()
    encrypted_avg = compute_encrypted_average(encrypted_salaries)
    compute_time = time.time() - start

    start = time.time()
    decrypted_avg = encrypted_avg.decrypt()[0]
    decrypt_time = time.time() - start

    expected_avg = sum(salaries) / len(salaries)

    print("--- Results ---")
    print(f"Decrypted average salary:  £{decrypted_avg:,.2f}")
    print(f"Expected (plaintext) avg:  £{expected_avg:,.2f}")
    print(f"Absolute error:            £{abs(decrypted_avg - expected_avg):.6f}")

    print("\n--- Timing ---")
    print(f"Encryption time (all {len(salaries)} salaries): {encrypt_time*1000:.2f} ms")
    print(f"Encrypted computation time:                    {compute_time*1000:.2f} ms")
    print(f"Decryption time:                               {decrypt_time*1000:.2f} ms")

    assert abs(decrypted_avg - expected_avg) < 0.01, "Average mismatch!"
    print("\n✅ Validation passed: encrypted average matches plaintext average.")

if __name__ == "__main__":
    main()
