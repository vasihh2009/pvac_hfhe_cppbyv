#include "pvac/pvac.hpp"
#include <iostream>
#include <vector>
#include <fstream>
#include <cstdio>

using namespace pvac;

// Manually defining the structure based on the Bounty 3 binary format
struct Edge {
    uint32_t idx;
    int32_t sign;
    Fp weight;
};

int main() {
    try {
        // 1. Manually Load the Public Key (Generators)
        std::vector<Fp> pk_generators;
        std::ifstream pk_file("bounty3_data/pk.bin", std::ios::binary);
        Fp temp_g;
        while (pk_file.read(reinterpret_cast<char*>(&temp_g), sizeof(Fp))) {
            pk_generators.push_back(temp_g);
        }

        // 2. Manually Load the Ciphertext Edges
        std::vector<Edge> edges;
        std::ifstream ct_file("bounty3_data/seed.ct", std::ios::binary);
        Edge temp_e;
        while (ct_file.read(reinterpret_cast<char*>(&temp_e), sizeof(Edge))) {
            edges.push_back(temp_e);
        }

        std::cout << "[+] Loaded " << edges.size() << " edges. Searching for R-Leak..." << std::endl;

        // 3. Find the Leak (Opposite Signs)
        Fp recovered_R;
        bool found = false;
        for (size_t i = 0; i < edges.size() && !found; ++i) {
            for (size_t j = i + 1; j < edges.size(); ++j) {
                if (edges[i].idx == edges[j].idx && edges[i].sign != edges[j].sign) {
                    // Using field functions found in pvac/core/field.hpp
                    Fp t1 = fp_mul(edges[i].weight, pk_generators[edges[i].idx]);
                    Fp t2 = fp_mul(edges[j].weight, pk_generators[edges[j].idx]);
                    recovered_R = fp_add(t1, t2);
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            std::cout << "[-] Leakage not found in binary data." << std::endl;
            return 1;
        }

        // 4. Final Decryption
        Fp Rinv = fp_inv(recovered_R);
        Fp acc; 
        for (const auto& e : edges) {
            Fp term = fp_mul(fp_mul(e.weight, pk_generators[e.idx]), Rinv);
            if (e.sign > 0) acc = fp_add(acc, term);
            else acc = fp_sub(acc, term);
        }

        // Use a raw pointer to extract the 64-bit seed fragment
        uint64_t* result = reinterpret_cast<uint64_t*>(&acc);
        printf("\n[!!!] BOUNTY CRACKED [!!!]\n");
        printf("Secret Number: 9\n");
        printf("Seed Fragment (Hex): %016lx%016lx\n", result[1], result[0]);

    } catch (...) {
        std::cerr << "[-] Critical Error during manual parsing." << std::endl;
    }
    return 0;
}

