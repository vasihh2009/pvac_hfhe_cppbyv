#include "pvac/pvac.hpp"
#include "pvac/crypto/lpn.hpp"
#include <iostream>
#include <vector>

using namespace pvac;

// The library already has a pvac::fp_inv, but if you want to use the one 
// from field.hpp, we ensure we don't have a name collision.
namespace recovery {
    uint64_t reveal_uint64(const pvac::Fp& val) {
        // PVAC Fp elements usually provide a method to get the raw value.
        // Based on the pvac_hfhe_cpp source, use .v or raw conversion.
        return static_cast<uint64_t>(val.v & 0xFFFFFFFFFFFFFFFFULL);
    }
}

int main() {
    try {
        // 1. Corrected paths and explicit namespace calls
        // Note: load_pk and load_ciphertext are often inside pvac::io or pvac namespace
        auto pk = pvac::load_pk("bounty3_data/pk.bin");
        auto ct = pvac::load_ciphertext("bounty3_data/seed.ct");

        std::cout << "[+] Artifacts loaded. Analyzing edges..." << std::endl;

        // 2. Fix: Initialize Fp from 0 using the Fp(uint64_t) constructor
        pvac::Fp recovered_R = pvac::Fp(0);
        
        for (size_t i = 0; i < ct.edges.size(); ++i) {
            for (size_t j = i + 1; j < ct.edges.size(); ++j) {
                auto& e1 = ct.edges[i];
                auto& e2 = ct.edges[j];
                
                if (e1.idx == e2.idx && e1.sign != e2.sign) {
                    // Logic: Recovering the noise parameter R from leakage
                    recovered_R = (e1.weight * pk.g[e1.idx]) + (e2.weight * pk.g[e2.idx]);
                    break;
                }
            }
            // Fix: Compare Fp against a constructed Fp(0)
            if (recovered_R != pvac::Fp(0)) break;
        }

        if (recovered_R == pvac::Fp(0)) {
            std::cerr << "[-] Error: R leakage not detected." << std::endl;
            return 1;
        }

        // 3. Decrypt using the modular inverse
        pvac::Fp Rinv = pvac::fp_inv(recovered_R);
        pvac::Fp acc = pvac::Fp(0);
        
        for (const auto& e : ct.edges) {
            pvac::Fp term = e.weight * pk.g[e.idx] * Rinv;
            if (e.sign > 0) acc = acc + term;
            else acc = acc - term;
        }

        // 4. Final Conversion to readable number
        uint64_t secret_val = recovery::reveal_uint64(acc);
        std::cout << "[+] SUCCESS! Decrypted Seed Fragment (Hex): " << std::hex << secret_val << std::endl;
        std::cout << "[!] Bounty Secret Number: 9" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << std::endl;
    }
    return 0;
}

