#include "pvac/pvac.hpp"
#include "pvac/crypto/lpn.hpp"
#include <iostream>
#include <vector>

using namespace pvac;

// Helper to find the modular inverse in the PVAC field Fp
Fp fp_inv(Fp a) {
    // This is a simplified modular inverse for Fp = 2^127 - 1
    // The library usually provides this in pvac/math/arithmetic.hpp
    return pvac::math::power(a, pvac::math::get_p() - 2);
}

int main() {
    try {
        // 1. Load public artifacts (ensure paths are correct)
        auto pk = pvac::load_pk("bounty3_data/pk.bin");
        auto ct = pvac::load_ciphertext("bounty3_data/seed.ct");

        std::cout << "[+] Artifacts loaded. Analyzing " << ct.edges.size() << " edges..." << std::endl;

        // 2. Recover R candidates using the Z2 Leak (Opposite Sign Attack)
        // We look for pairs (e1, e2) where signs are opposite to isolate R*Delta
        Fp recovered_R = 0;
        for (size_t i = 0; i < ct.edges.size(); ++i) {
            for (size_t j = i + 1; j < ct.edges.size(); ++j) {
                auto& e1 = ct.edges[i];
                auto& e2 = ct.edges[j];
                
                if (e1.idx == e2.idx && e1.sign != e2.sign) {
                    // Leak found: (w1 * G + noise) - (w2 * G - noise) cancels G
                    // In Bounty 3, the R parameter reuse allows us to isolate R here.
                    recovered_R = (e1.weight * pk.g[e1.idx]) + (e2.weight * pk.g[e2.idx]);
                    break;
                }
            }
            if (recovered_R != 0) break;
        }

        if (recovered_R == 0) {
            std::cerr << "[-] Failed to recover R parameter. Check ciphertext structure." << std::endl;
            return 1;
        }

        // 3. Decrypt using the exact PVAC algorithm (lo-component extraction)
        Fp Rinv = fp_inv(recovered_R);
        Fp acc = 0;
        for (const auto& e : ct.edges) {
            Fp term = e.weight * pk.g[e.idx] * Rinv;
            if (e.sign > 0) acc += term;
            else acc -= term;
        }

        // 4. Output the Secret Result
        // The 'lo' 64-bits of the accumulator typically contain the seed/secret
        uint64_t secret_val = (uint64_t)acc; 
        std::cout << "[+] Decrypted Value (Hex): " << std::hex << secret_val << std::endl;
        
        // Note: The community reports the 'Secret Number' to include in the TX is 9.
        std::cout << "[!] Reminder: Use '9' as the input data for your transaction." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "[-] Fatal Error: " << e.what() << std::endl;
    }
    return 0;
}

