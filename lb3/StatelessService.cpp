//
// Created by Вероника Мельцова on 17.11.2025.
//
#include "StatelessService.h"
#include <stdexcept>

namespace GaloisField {
    uint8_t StatelessService::add(uint8_t a, uint8_t b) const{
        return a ^ b;
    }
    uint8_t StatelessService::multiply(uint8_t a, uint8_t b, uint16_t modulus) const{
       uint8_t res = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) == 1){
                res ^= a;
            }
            bool overflow = (a & 0x80) != 0;
            a <<= 1;
            if (overflow) {
               a ^= (modulus & 0xFF);
            }
            b >>= 1;
        }
        return res;
    }
    uint8_t StatelessService::inverse(uint8_t a, uint16_t modulus) const{
        if (a == 0){
            return 0;
        }
        uint16_t r0 = modulus, r1 = a;
        uint8_t t0 = 0, t1 =1;
        while (r1 != 0) {
            uint8_t q = 0;
            uint16_t temp_r = r0;
            while (temp_r >= r1) {
                int shift = 0;
                uint16_t temp_r1 = r1;
                int deg_temp_r = 0;
                for(int i=15; i>=0; --i) if((temp_r >> i) & 1) { deg_temp_r = i; break; }
                int deg_r1 = 0;
                for(int i=15; i>=0; --i) if((r1 >> i) & 1) { deg_r1 = i; break; }
                if(deg_temp_r < deg_r1) break; // Выходим, если степень остатка стала меньше
                shift = deg_temp_r - deg_r1;
                q ^= (1 << shift);
                temp_r ^= (r1 << shift);
            }

            uint8_t temp_t = t0 ^ multiply(q, t1, modulus);
            t0 = t1;
            t1 = temp_t;
            r0 = r1;
            r1 = temp_r;
        }
        if (r0 != 1) {
            throw std::runtime_error("Inverse does not exist.");
        }

        return t0;
    }

    uint16_t poly_remainder(uint16_t dividend, uint16_t divisor) {
        int divisor_deg = 0;
        for (int i = 15; i >= 0; --i) {
            if ((divisor >> i) & 1) {
                divisor_deg = i;
                break;
            }
        }
        for (int i = 15; i >= divisor_deg; --i) {
            if ((dividend >> i) & 1) {
                dividend ^= (divisor << (i - divisor_deg));
            }
        }
        return dividend;
    }

    bool StatelessService::isIrreducible(uint16_t p) const {
        if (p < 0x100 || p > 0x1FF) {
            return false;
        }
        if ((p & 1) == 0) {
            return false;
        }
        for (uint16_t divisor = 3; divisor <= 0x1F; divisor += 2) {
            int divisor_deg = 0;
            for (int i = 15; i >= 0; --i) {
                if ((divisor >> i) & 1) {
                    divisor_deg = i;
                    break;
                }
            }
            if (divisor_deg > 4) {
                continue;
            }
            if (poly_remainder(p, divisor) == 0) {
                return false;
            }
        }
        return true;
    }

    std::vector<uint16_t> StatelessService::findAllIrreducible() const {
        std::vector<uint16_t> result;
        for (uint16_t p = 0x101; p <= 0x1FF; p += 2) {
            if (isIrreducible(p)) {
                result.push_back(p);
            }
        }
        return result;
    }
}