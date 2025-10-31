//
// Created by Вероника on 26.10.2025.
//

#include <iostream>
#include "StatelessService.h"

void demonstrate_gcd() {
    std::cout << "НОД (Алгоритм Евклида)\n";
    big_int a("1147"), b("851");
    std::cout << "НОД(" << a << ", " << b << ") = " << CryptoService::Gcd(a, b) << std::endl;
    std::cout << std::endl;
}

void demonstrate_extended_gcd() {
    std::cout << "Расширенный алгоритм Евклида\n";
    big_int a("240"), b("46");
    big_int x, y;
    big_int gcd = CryptoService::ExtendedGcd(a, b, x, y);
    std::cout << "НОД(" << a << ", " << b << ") = " << gcd << std::endl;
    std::cout << "Коэффициенты: x = " << x << ", y = " << y << std::endl;
    std::cout << "Проверка: " << a << "*" << x << " + " << b << "*" << y << " = " << a * x + b * y << std::endl;
    std::cout << std::endl;
}

void demonstrate_mod_pow() {
    std::cout << "Возведение в степень по модулю\n";
    big_int base("5"), exp("117"), mod("19");
    std::cout << base << "^" << exp << " mod " << mod << " = " << CryptoService::ModPow(base, exp, mod) << std::endl;
    std::cout << std::endl;
}

void demonstrate_legendre() {
    std::cout << "Символа Лежандра\n";
    big_int a1("2"), p1("7");
    big_int a2("3"), p2("7");
    big_int a3("7"), p3("7");
    std::cout << "Символ Лежандра (" << a1 << "/" << p1 << ") = " << CryptoService::LegendreSymbol(a1, p1) << std::endl;
    std::cout << "Символ Лежандра (" << a2 << "/" << p2 << ") = " << CryptoService::LegendreSymbol(a2, p2) << std::endl;
    std::cout << "Символ Лежандра (" << a3 << "/" << p3 << ") = " << CryptoService::LegendreSymbol(a3, p3) << std::endl;
    std::cout << std::endl;
}

void demonstrate_jacobi() {
    std::cout << "Символ Якоби\n";
    big_int a("1001"), n("9907");
    std::cout << "Символ Якоби (" << a << "/" << n << ") = " << CryptoService::JacobiSymbol(a, n) << std::endl;
    std::cout << std::endl;
}

int main() {
    setlocale(LC_ALL, "Russian");

    try {
        demonstrate_gcd();
        demonstrate_extended_gcd();
        demonstrate_mod_pow();
        demonstrate_legendre();
        demonstrate_jacobi();
    } catch (const std::exception& e) {
        std::cerr << "Произошла ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}