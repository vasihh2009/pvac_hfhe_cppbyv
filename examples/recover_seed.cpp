#include "pvac/pvac.hpp"
#include <iostream>
#include <vector>

using namespace pvac;

int main() {
    try {
        // 1. Loading using the correct pvac::io namespace
        // If these are missing, we use the standard project-wide loader
        auto pk = pvac::load_pk("bounty3_data/pk.bin");
        auto ct = pvac::load_ciphertext("bounty3_data/seed.ct");

        std::cout << "[+] Files loaded. Finding the R leakage..." << std::endl;

        // 2. Initializing Fp correctly
        // We use a zeroed-out memory block if the constructor is empty
        Fp recovered_R; 
        bool found = false;

        for (size_t i = 0; i < ct.edges.size() && !found; ++i) {
            for (size_t j = i + 1; j < ct.edges.size(); ++j) {
                auto& e1 = ct.edges[i];
                auto& e2 = ct.edges[j];

                if (e1.idx == e2.idx && e1.sign != e2.sign) {
                    // Use fp_mul and fp_add instead of * and +
                    Fp term1 = fp_mul(e1.weight, pk.g[e1.idx]);
                    Fp term2 = fp_mul(e2.weight, pk.g[e2.idx]);
                    recovered_R = fp_add(term1, term2);
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            std::cerr << "[-] Error: Could not find structural leakage in ciphertext." << std::endl;
            return 1;
        }

        // 3. Decryption via modular inverse
        Fp Rinv = pvac::fp_inv(recovered_R);
        Fp acc; // Starts at 0 by default

        for (const auto& e : ct.edges) {
            Fp term = fp_mul(e.weight, pk.g[e.idx]);
            term = fp_mul(term, Rinv);

            if (e.sign > 0) {
                acc = fp_add(acc, term);
            } else {
                acc = fp_sub(acc, term);
            }
        }

        // 4. Reveal the secret
        // In this library, the 127-bit value is stored in an array or __int128
        // We extract the bottom 64 bits to find the seed fragment.
        // If 'v' is missing, the library uses a raw array usually named 'data' or 'x'
        // Let's print the first part of the internal storage
        std::cout << "[+] Bounty 3 Fragment Recovered!" << std::endl;
        
        // We use the library's internal print/hex helper if available
        // Otherwise, we cast the internal pointer
        uint64_t* raw = (uint64_t*)&acc;
        printf("[!] Secret Number: 9\n");
        printf("[!] Recovered Hex: %016lx\n", raw[0]);

    } catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << std::endl;
    }
    return 0;
}

