//
// Created by Вероника on 26.10.2025.
//

#include "PrimalityTest.h"
#include <cmath>
#include <stdexcept>
#include <boost/random.hpp>
#include <chrono>

bool PrimalityTest::IsPrime(const big_int& n, double min_probability) const {
    if (n < big_int(2)) {
        return false;
    }
    if (n == big_int(2) || n == big_int(3)) {
        return true;
    }
    if (n % big_int(2) == big_int(0)) {
        return false;
    }

    if (min_probability < 0.5 || min_probability >= 1.0) {
        throw std::invalid_argument("Вероятность должна быть в диапазоне [0.5, 1)");
    }

    int k = static_cast<int>(ceil(log2(1.0 / (1.0 - min_probability))));

    for (int i = 0; i < k; ++i) {
        if (!PerformSingleIteration(n)) {
            return false;
        }
    }
    return true;
}


big_int PrimalityTest::GenerateRandomBigInt(const big_int& min, const big_int& max) {
    if (min > max) {
        throw std::invalid_argument("min > max");
    }
    if (min == max) {
        return min;
    }

    thread_local static boost::random::mt19937_64 gen(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()
    );

    boost::random::uniform_int_distribution<big_int> dist(min, max);
    return dist(gen);
}


bool FermatTest::PerformSingleIteration(const big_int& n) const {
    big_int a = GenerateRandomBigInt(2, n - 2);
    if (CryptoService::Gcd(a, n) > 1) {
        return false;
    }
    return CryptoService::ModPow(a, n - 1, n) == 1;
}

bool SolovayStrassenTest::PerformSingleIteration(const big_int& n) const {
    big_int a = GenerateRandomBigInt(2, n - 2);
    if (CryptoService::Gcd(a, n) > 1) {
        return false;
    }
    int jacobi = CryptoService::JacobiSymbol(a, n);
    big_int mod_pow = CryptoService::ModPow(a, (n - 1) / 2, n);
    big_int jacobi_big = (jacobi == -1) ? (n - 1) : big_int(jacobi);
    return mod_pow == jacobi_big;
}

bool MillerRabinTest::PerformSingleIteration(const big_int& n) const {
    big_int d = n - 1;
    big_int s = 0;
    while (d % 2 == 0) {
        d /= 2;
        s++;
    }
    big_int a = GenerateRandomBigInt(2, n - 2);
    big_int x = CryptoService::ModPow(a, d, n);
    if (x == 1 || x == n - 1) {
        return true;
    }
    for (big_int r = 1; r < s; r++) {
        x = CryptoService::ModPow(x, 2, n);
        if (x == n - 1) {
            return true;
        }
    }
    return false;
}