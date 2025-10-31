//
// Created by Вероника on 26.10.2025.
//

#ifndef CRYPTOGRAPHY_PRIMALITYTEST_H
#define CRYPTOGRAPHY_PRIMALITYTEST_H

#ifndef PRIMALITY_TEST_H
#define PRIMALITY_TEST_H
#include "StatelessService.h"
#include <boost/multiprecision/gmp.hpp>

// Определяем big_int как тип из Boost
using big_int = boost::multiprecision::mpz_int;

/**
 * @interface IPrimalityTest
 * @brief Определяет общий интерфейс для всех тестов простоты.
 */
class IPrimalityTest {
public:
    virtual ~IPrimalityTest() = default;

    /**
     * @brief Проверяет, является ли число n вероятно простым.
     * @param n Тестируемое число.
     * @param min_probability Минимальная вероятность того, что число простое, если тест пройден.
     * @return true, если число вероятно простое, иначе false.
     */
    virtual bool IsPrime(const big_int& n, double min_probability) const = 0;
};

/**
 * @class PrimalityTest
 * @brief Абстрактный базовый класс для вероятностных тестов простоты (Шаблонный метод).
 */
class PrimalityTest : public IPrimalityTest {
public:
    // Это наш "Шаблонный метод", он определяет скелет алгоритма.
    bool IsPrime(const big_int& n, double min_probability) const override;
    static big_int GenerateRandomBigInt(const big_int& min, const big_int& max);

protected:
    /**
     * @brief Выполняет одну итерацию теста. Реализуется в дочерних классах.
     * @param n Тестируемое число.
     * @return true, если итерация пройдена, иначе false.
     */
    virtual bool PerformSingleIteration(const big_int& n) const = 0;

    /**
     * @brief Вспомогательный метод для генерации случайного числа в диапазоне.
     *        Доступен только этому классу и его наследникам.
     * @param min Нижняя граница (включительно).
     * @param max Верхняя граница (включительно).
     * @return Случайное big_int в диапазоне [min, max].
     */
};

// --- Конкретные реализации тестов ---

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
