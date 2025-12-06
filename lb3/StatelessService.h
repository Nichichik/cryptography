//
// Created by Вероника Мельцова on 17.11.2025.
//

#ifndef CRYPTOGRAPHY_STATELESSSERVICE_H
#define CRYPTOGRAPHY_STATELESSSERVICE_H
#include <vector>
#include <cstdint>

namespace GaloisField{
    class StatelessService{
    public:
        static const uint16_t AES_MODULUS = 0x11B;
        uint8_t add(uint8_t a, uint8_t b) const;
        uint8_t multiply(uint8_t a, uint8_t b, uint16_t modulus = AES_MODULUS) const;
        uint8_t inverse(uint8_t a, uint16_t modulus = AES_MODULUS) const;
        bool isIrreducible(uint16_t p) const;
        std::vector<uint16_t> findAllIrreducible() const;
    };
}
#endif //CRYPTOGRAPHY_STATELESSSERVICE_H