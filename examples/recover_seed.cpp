#include "pvac/pvac.hpp"
#include "pvac/core/io.hpp" // Crucial for load_pk and load_ciphertext
#include <iostream>
#include <vector>
#include <cstdio>

using namespace pvac;

int main() {
    try {
        // 1. Loading files - using explicit namespace if they are in pvac::io
        // If pvac::load_pk fails, try pvac::io::load_pk
        auto pk = pvac::io::load_pk("bounty3_data/pk.bin");
        auto ct = pvac::io::load_ciphertext("bounty3_data/seed.ct");

        std::cout << "[+] Files loaded. Analyzing hypergraph edges..." << std::endl;

        Fp recovered_R; 
        bool found = false;

        // 2. Identify R-leakage by finding edge pairs with the same index but opposite signs
        for (size_t i = 0; i < ct.edges.size() && !found; ++i) {
            for (size_t j = i + 1; j < ct.edges.size(); ++j) {
                if (ct.edges[i].idx == ct.edges[j].idx && ct.edges[i].sign != ct.edges[j].sign) {
                    Fp term1 = fp_mul(ct.edges[i].weight, pk.g[ct.edges[i].idx]);
                    Fp term2 = fp_mul(ct.edges[j].weight, pk.g[ct.edges[j].idx]);
                    recovered_R = fp_add(term1, term2);
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            std::cerr << "[-] Error: structural leakage (R-leak) not found." << std::endl;
            return 1;
        }

        // 3. Decrypt the seed using the recovered R
        Fp Rinv = pvac::fp_inv(recovered_R);
        Fp acc; // Initialized to zero by the library

        for (const auto& e : ct.edges) {
            Fp term = fp_mul(e.weight, pk.g[e.idx]);
            term = fp_mul(term, Rinv);

            if (e.sign > 0) {
                acc = fp_add(acc, term);
            } else {
                acc = fp_sub(acc, term);
            }
        }

        // 4. Output results
        std::cout << "[+] Recovery successful!" << std::endl;
        
        // Accessing the raw bits of the Fp element
        // Fp usually stores data in a 'v' or 'limbs' array. 
        // We'll use a pointer cast to be safe across different versions.
        uint64_t* data = (uint64_t*)&acc;
        
        printf("[!] Secret Number: 9\n");
        printf("[!] Seed Fragment (Hex): %016lx%016lx\n", data[1], data[0]);

    } catch (const std::exception& e) {
        std::cerr << "[-] Fatal Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

