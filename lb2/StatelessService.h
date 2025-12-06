//
// Created by Вероника on 26.10.2025.
//

#ifndef CRYPTOGRAPHY_STATELESSSERVICE_H
#define CRYPTOGRAPHY_STATELESSSERVICE_H

#include <boost/multiprecision/gmp.hpp>

using big_int = boost::multiprecision::mpz_int;
class CryptoService {
public:
    CryptoService() = delete;
    static int LegendreSymbol(const big_int& a, const big_int& p);
    static int JacobiSymbol(big_int a, big_int n);
    static big_int Gcd(big_int a, big_int b);
    static big_int ExtendedGcd(big_int a, big_int b, big_int& x, big_int& y);
    static big_int ModPow(big_int base, big_int exp, const big_int& mod);
};


#endif //CRYPTOGRAPHY_STATELESSSERVICE_H
