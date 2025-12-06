//
// Created by Вероника on 26.10.2025.
//

#ifndef CRYPTOGRAPHY_PRIMALITYTEST_H
#define CRYPTOGRAPHY_PRIMALITYTEST_H

#ifndef PRIMALITY_TEST_H
#define PRIMALITY_TEST_H
#include "StatelessService.h"
#include <boost/multiprecision/gmp.hpp>

using big_int = boost::multiprecision::mpz_int;
class IPrimalityTest {
public:
    virtual ~IPrimalityTest() = default;
    virtual bool IsPrime(const big_int& n, double min_probability) const = 0;
};

class PrimalityTest : public IPrimalityTest {
public:
    bool IsPrime(const big_int& n, double min_probability) const override;
    static big_int GenerateRandomBigInt(const big_int& min, const big_int& max);

protected:
    virtual bool PerformSingleIteration(const big_int& n) const = 0;
};


class FermatTest : public PrimalityTest {
protected:
    bool PerformSingleIteration(const big_int& n) const override;
};

class SolovayStrassenTest : public PrimalityTest {
protected:
    bool PerformSingleIteration(const big_int& n) const override;
};

class MillerRabinTest : public PrimalityTest {
protected:
    bool PerformSingleIteration(const big_int& n) const override;
};

#endif //PRIMALITY_TEST_H

#endif //CRYPTOGRAPHY_PRIMALITYTEST_H
