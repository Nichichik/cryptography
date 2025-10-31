//
// Created by Вероника on 26.10.2025.
//

#include "StatelessService.h"
#include <stdexcept>
#include <utility>


big_int CryptoService::ModPow(big_int base, big_int exp, const big_int& mod) {
    if (mod == 0) {
        throw std::invalid_argument("Модуль не может быть нулевым");
    }
    if (exp < 0) {
        throw std::invalid_argument("Степень не может быть отрицательной");
    }

    big_int result(1);
    base = (base % mod + mod) % mod;

    while (exp != 0) {
        if (exp % big_int(2) == big_int(1)) {
            result = (result * base) % mod;
        }
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

int CryptoService::LegendreSymbol(const big_int& a, const big_int& p) {
    if (p <= big_int(2) || p % big_int(2) == big_int(0)) {
        throw std::invalid_argument("p должно быть нечетным простым числом");
    }
    return JacobiSymbol(a, p);
}

int CryptoService::JacobiSymbol(big_int a, big_int n) {
    if (n <= big_int(0) || n % big_int(2) == big_int(0)) {
        throw std::invalid_argument("n должно быть положительным нечетным числом");
    }
    if (Gcd(a, n) != big_int(1)) {
        return 0;
    }

    int r = 1;
    if (a < 0) {
        a = -a;
        if (n % big_int(4) == big_int(3)) {
            r = -r;
        }
    }

    a %= n;

    while (a != 0) {
        int t = 0;
        while (a % big_int(2) == big_int(0)) {
            t++;
            a /= big_int(2);
        }

        if (t % 2 == 1) {
            big_int n_mod_8 = n % big_int(8);
            if (n_mod_8 == big_int(3) || n_mod_8 == big_int(5)) {
                r = -r;
            }
        }

        if (a % big_int(4) == big_int(3) && n % big_int(4) == big_int(3)) {
            r = -r;
        }
        std::swap(a, n);
        a %= n;
    }

    return r;
}

big_int CryptoService::Gcd(big_int a, big_int b) {
    using boost::multiprecision::abs;
    a = abs(a);
    b = abs(b);

    while (b != 0) {
        a %= b;
        std::swap(a, b);
    }
    return a;
}

big_int CryptoService::ExtendedGcd(big_int a, big_int b, big_int& x, big_int& y) {
    if (a == 0) {
        x = big_int(0);
        y = big_int(1);
        return b;
    }

    big_int x1, y1;
    big_int gcd = ExtendedGcd(b % a, a, x1, y1);

    x = y1 - (b / a) * x1;
    y = x1;

    return gcd;
}