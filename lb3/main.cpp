//
// Created by Вероника Мельцова on 17.11.2025.
//

#include <iostream>
#include "StatelessService.h"

int main() {
    using namespace GaloisField;
    StatelessService gf_service;

    uint8_t a = 0x57;
    uint8_t b = 0x83;

    uint8_t sum = gf_service.add(a, b);
    std::cout << "0x57 + 0x83 = 0x" << std::hex << (int)sum << std::endl;

    uint8_t product = gf_service.multiply(a, b, StatelessService::AES_MODULUS);
    std::cout << "0x57 * 0x83 (mod 0x11B) = 0x" << std::hex << (int)product << std::endl;

    uint8_t val_to_invert = 0x53;
    uint8_t inverse_val = gf_service.inverse(val_to_invert, StatelessService::AES_MODULUS);
    std::cout << "Inverse of 0x53 (mod 0x11B) = 0x" << std::hex << (int)inverse_val << std::endl;

    uint8_t check = gf_service.multiply(val_to_invert, inverse_val, StatelessService::AES_MODULUS);
    std::cout << "Check: 0x53 * 0xCA = 0x" << std::hex << (int)check << std::endl;

    std::cout << "\nFinding all irreducible polynomials of degree 8..." << std::endl;
    std::vector<uint16_t> irreducibles = gf_service.findAllIrreducible();
    std::cout << "Found " << std::dec << irreducibles.size() << " irreducible polynomials." << std::endl;
    for (uint16_t p : irreducibles) {
        std::cout << "0x" << std::hex << p << " ";
    }
    std::cout << std::endl;

    return 0;
}