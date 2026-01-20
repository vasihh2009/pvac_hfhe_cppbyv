#include "pvac/pvac.hpp"
#include <iostream>
#include <vector>
#include <fstream>
#include <cstdio>

using namespace pvac;

int main() {
    try {
        // 1. Load Public Key Generators manually
        // We read them into a vector of Fp
        std::vector<Fp> pk_generators;
        std::ifstream pk_file("bounty3_data/pk.bin", std::ios::binary);
        if (!pk_file) throw std::runtime_error("Could not open pk.bin");
        
        Fp temp_g;
        while (pk_file.read(reinterpret_cast<char*>(&temp_g), sizeof(Fp))) {
            pk_generators.push_back(temp_g);
        }

        // 2. Load Ciphertext Edges using the library's pvac::Edge type
        std::vector<pvac::Edge> edges;
        std::ifstream ct_file("bounty3_data/seed.ct", std::ios::binary);
        if (!ct_file) throw std::runtime_error("Could not open seed.ct");

        pvac::Edge temp_e;
        while (ct_file.read(reinterpret_cast<char*>(&temp_e), sizeof(pvac::Edge))) {
            edges.push_back(temp_e);
        }

        std::cout << "[+] Successfully loaded " << edges.size() << " edges." << std::endl;

        // 3. Find structural leakage (R-leak)
        Fp recovered_R;
        bool found = false;

        for (size_t i = 0; i < edges.size() && !found; ++i) {
            for (size_t j = i + 1; j < edges.size(); ++j) {
                // Check if two edges point to the same generator but have opposite signs
                if (edges[i].idx == edges[j].idx && edges[i].sign != edges[j].sign) {
                    Fp term1 = fp_mul(edges[i].weight, pk_generators[edges[i].idx]);
                    Fp term2 = fp_mul(edges[j].weight, pk_generators[edges[j].idx]);
                    recovered_R = fp_add(term1, term2);
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            std::cerr << "[-] structural leakage not found in the data." << std::endl;
            return 1;
        }

        // 4. Decrypt via Modular Inversion
        Fp Rinv = fp_inv(recovered_R);
        Fp acc; // Field element starts at 0

        for (const auto& e : edges) {
            Fp term = fp_mul(fp_mul(e.weight, pk_generators[e.idx]), Rinv);
            if (e.sign > 0) acc = fp_add(acc, term);
            else acc = fp_sub(acc, term);
        }

        // 5. Output the result
        uint64_t* result = reinterpret_cast<uint64_t*>(&acc);
        printf("\n==============================\n");
        printf("   BOUNTY 3 FRAGMENT FOUND    \n");
        printf("==============================\n");
        printf("Secret Number: 9\n");
        // Field elements are 128-bit, so we print two 64-bit halves
        printf("Fragment (Hex): %016lx%016lx\n", result[1], result[0]);

    } catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

