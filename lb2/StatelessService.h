//
// Created by Вероника on 26.10.2025.
//

#ifndef CRYPTOGRAPHY_STATELESSSERVICE_H
#define CRYPTOGRAPHY_STATELESSSERVICE_H

#include <boost/multiprecision/gmp.hpp> // Используем быстрый GMP бэкенд

// Теперь big_int - это высокопроизводительный тип из Boost
using big_int = boost::multiprecision::mpz_int; // Убедитесь, что путь к вашему big_int.h верный

/**
 * @class CryptoService
 * @brief Предоставляет набор статических методов для выполнения
 *        основных криптографических вычислений.
 *        Класс является stateless, т.е. не хранит состояния между вызовами.
 */
class CryptoService {
public:
    // Запрещаем создавать экземпляры этого класса
    CryptoService() = delete;

    /**
     * @brief Вычисляет символ Лежандра (a/p).
     * @param a Целое число.
     * @param p Нечетное простое число.
     * @return 1, если a - квадратичный вычет по модулю p;
     *        -1, если a - квадратичный невычет по модулю p;
     *         0, если a делится на p.
     */
    static int LegendreSymbol(const big_int& a, const big_int& p);

    /**
     * @brief Вычисляет символ Якоби (a/n).
     * @param a Целое число.
     * @param n Положительное нечетное целое число.
     * @return 0, 1 или -1 в зависимости от свойств чисел.
     */
    static int JacobiSymbol(big_int a, big_int n);

    /**
     * @brief Вычисляет Наибольший Общий Делитель (НОД) двух целых чисел
     *        с помощью алгоритма Евклида.
     * @param a Первое число.
     * @param b Второе число.
     * @return НОД(a, b).
     */
    static big_int Gcd(big_int a, big_int b);

    /**
     * @brief Находит НОД и решает диофантово уравнение ax + by = gcd(a, b)
     *        с помощью расширенного алгоритма Евклида.
     * @param a Первое число.
     * @param b Второе число.
     * @param x Ссылка для возврата первого коэффициента Безу.
     * @param y Ссылка для возврата второго коэффициента Безу.
     * @return НОД(a, b).
     */
    static big_int ExtendedGcd(big_int a, big_int b, big_int& x, big_int& y);

    /**
     * @brief Выполняет операцию возведения в степень по модулю (base^exp % mod)
     *        с помощью алгоритма бинарного возведения в степень.
     * @param base Основание.
     * @param exp Показатель степени.
     * @param mod Модуль.
     * @return Результат (base^exp) % mod.
     */
    static big_int ModPow(big_int base, big_int exp, const big_int& mod);
};


#endif //CRYPTOGRAPHY_STATELESSSERVICE_H
