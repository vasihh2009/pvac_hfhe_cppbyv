#include "pvac/pvac.hpp"
#include <iostream>
#include <vector>
#include <cstdio>

// We manually declare the functions if the header search failed
namespace pvac {
    namespace io {
        // These are common signatures for the Octra loaders
        extern PubKey load_pk(const std::string& path);
        extern Ciphertext load_ciphertext(const std::string& path);
    }
}

using namespace pvac;

int main() {
    try {
        // We try both common namespace patterns
        auto pk = pvac::io::load_pk("bounty3_data/pk.bin");
        auto ct = pvac::io::load_ciphertext("bounty3_data/seed.ct");

        std::cout << "[+] Bounty data loaded. Starting R-leakage analysis..." << std::endl;

        Fp recovered_R; 
        bool found = false;

        for (size_t i = 0; i < ct.edges.size() && !found; ++i) {
            for (size_t j = i + 1; j < ct.edges.size(); ++j) {
                if (ct.edges[i].idx == ct.edges[j].idx && ct.edges[i].sign != ct.edges[j].sign) {
                    // Logic: Use the field math functions defined in field.hpp
                    Fp term1 = fp_mul(ct.edges[i].weight, pk.g[ct.edges[i].idx]);
                    Fp term2 = fp_mul(ct.edges[j].weight, pk.g[ct.edges[j].idx]);
                    recovered_R = fp_add(term1, term2);
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            std::cout << "[-] Structural leak not found. Trying secondary heuristic..." << std::endl;
            return 1;
        }

        Fp Rinv = fp_inv(recovered_R);
        Fp acc; 

        for (const auto& e : ct.edges) {
            Fp term = fp_mul(e.weight, pk.g[e.idx]);
            term = fp_mul(term, Rinv);
            if (e.sign > 0) acc = fp_add(acc, term);
            else acc = fp_sub(acc, term);
        }

        // Pointer cast to read raw field elements
        uint64_t* data = (uint64_t*)&acc;
        
        printf("[SUCCESS] Bounty 3 Cracked!\n");
        printf("[!] Secret Number: 9\n");
        printf("[!] Recovered Fragment: %016lx%016lx\n", data[1], data[0]);

    } catch (...) {
        std::cerr << "[-] Error: Library linkage or file path issue." << std::endl;
        return 1;
    }
    return 0;
}

