//
// Created by Вероника Мельцова on 24.11.2025.
//

#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <memory>
#include <chrono>
#include <iomanip>

#include "Magenta.h"
#include "../lb1/SymmetricInterfaces.h" // Убедись, что путь к твоим интерфейсам правильный

namespace fs = std::filesystem;
using byte_array = std::vector<unsigned char>;
using ExtraParams = std::map<std::string, std::any>;


byte_array read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open file for reading: " << path << std::endl;
        return {};
    }
    return byte_array((std::istreambuf_iterator<char>(in)), {});
}

bool compare_buffers(const byte_array& a, const byte_array& b) {
    return a == b;
}


void test_magenta_mode(const std::string& file, size_t key_size_bits, CipherMode mode) {
    std::cout << "\n==========================================================\n";
    std::cout << "[MAGENTA] Testing file: " << file << "\n"
              << "  Config: Block=128 bits, Key=" << key_size_bits << " bits\n"
              << "  Mode: ";

    switch (mode) {
        case CipherMode::ECB: std::cout << "ECB"; break;
        case CipherMode::CBC: std::cout << "CBC"; break;
        case CipherMode::PCBC: std::cout << "PCBC"; break;
        case CipherMode::CFB: std::cout << "CFB"; break;
        case CipherMode::OFB: std::cout << "OFB"; break;
        case CipherMode::CTR: std::cout << "CTR"; break;
        case CipherMode::RANDOM_DELTA: std::cout << "Random Delta"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << std::endl;

    byte_array key(key_size_bits / 8, 0xAB);
    byte_array iv(16, 0xCD);

    byte_array original = read_file(file);
    if (original.empty()) {
        std::cout << "Skipped empty or unreadable file." << std::endl;
        return;
    }

    std::string encrypted_file = file + ".mag.enc";
    std::string decrypted_file = file + ".mag.dec";

    try {
        auto magenta_encrypt = std::make_unique<Magenta>(key_size_bits);
        CipherContext ctx(std::move(magenta_encrypt), key, mode, PaddingScheme::PKCS7, iv);
        std::cout << "  Encrypting... ";
        auto start_time = std::chrono::high_resolution_clock::now();
        ctx.encrypt(file, encrypted_file).get();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "Done in " << duration << " ms." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "  ERROR during encryption: " << e.what() << std::endl;
        return;
    }

    try {
        auto magenta_decrypt = std::make_unique<Magenta>(key_size_bits);
        CipherContext ctx(std::move(magenta_decrypt), key, mode, PaddingScheme::PKCS7, iv);

        std::cout << "  Decrypting... ";
        auto start_time = std::chrono::high_resolution_clock::now();
        ctx.decrypt(encrypted_file, decrypted_file).get();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "Done in " << duration << " ms." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "  ERROR during decryption: " << e.what() << std::endl;
        return;
    }

    std::cout << "  Verifying result... ";
    byte_array decrypted_from_file = read_file(decrypted_file);
    if (compare_buffers(original, decrypted_from_file)) {
        std::cout << "SUCCESS." << std::endl;
    } else {
        std::cout << "FAILURE: Decrypted file does not match the original." << std::endl;
    }
}

int main() {
    try {
        fs::path test_dir = "../lb1/test_files";
        if (!fs::exists(test_dir)) {
            std::cerr << "Test directory not found at: " << fs::absolute(test_dir) << std::endl;
            return 1;
        }
        fs::current_path(test_dir);
        std::cout << "Current test directory: " << fs::current_path() << "\n";

        std::vector<std::string> files_to_test = {"Homework.docx", "flowers.jpg"};
        std::vector<size_t> key_sizes_to_test = {128, 192, 256};
        std::vector<CipherMode> modes_to_test = {
            CipherMode::ECB,
            CipherMode::CBC,
            CipherMode::PCBC,
            CipherMode::CFB,
            CipherMode::OFB
        };

        for (const auto& file : files_to_test) {
            for (auto key_size : key_sizes_to_test) {
                for (auto mode : modes_to_test) {
                    test_magenta_mode(file, key_size, mode);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "A fatal error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}