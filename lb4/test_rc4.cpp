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

#include "RC4.h"
#include "../lb1/SymmetricInterfaces.h"

namespace fs = std::filesystem;
using byte_array = std::vector<unsigned char>;

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


void test_rc4_mode(const std::string& file_path, const byte_array& key) {
    std::cout << "\n==========================================================\n";
    std::cout << "[RC4] Testing file: " << file_path << "\n"
              << "  Key length: " << key.size() << " bytes" << std::endl;

    byte_array original = read_file(file_path);
    if (original.empty()) {
        std::cout << "Skipped empty or unreadable file\n";
        return;
    }

    byte_array encrypted_mem;
    byte_array decrypted_mem;

    {
        auto rc4_encrypt_mem = std::make_unique<RC4>();
        CipherContext ctx_encrypt_mem(std::move(rc4_encrypt_mem), key, CipherMode::ECB, PaddingScheme::Zeros);
        ctx_encrypt_mem.encrypt(original, encrypted_mem).get();
    }
    {
        auto rc4_decrypt_mem = std::make_unique<RC4>();
        CipherContext ctx_decrypt_mem(std::move(rc4_decrypt_mem), key, CipherMode::ECB, PaddingScheme::Zeros);
        ctx_decrypt_mem.decrypt(encrypted_mem, decrypted_mem).get();
    }

    if (compare_buffers(original, decrypted_mem)) {
        std::cout << "  In-memory test: OK\n";
    } else {
        std::cout << "  In-memory test: FAILED\n";
    }

    std::string encrypted_file = file_path + ".rc4.enc";
    std::string decrypted_file = file_path + ".rc4.dec";

    {
        auto rc4_encrypt_file = std::make_unique<RC4>();
        CipherContext ctx_encrypt_file(std::move(rc4_encrypt_file), key, CipherMode::ECB, PaddingScheme::Zeros);

        auto start_time = std::chrono::high_resolution_clock::now();
        ctx_encrypt_file.encrypt(file_path, encrypted_file).get();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "  File encrypt time: " << encrypt_duration << " ms" << std::endl;
    }

    {
        auto rc4_decrypt_file = std::make_unique<RC4>();
        CipherContext ctx_decrypt_file(std::move(rc4_decrypt_file), key, CipherMode::ECB, PaddingScheme::Zeros);

        auto start_time = std::chrono::high_resolution_clock::now();
        ctx_decrypt_file.decrypt(encrypted_file, decrypted_file).get();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "  File decrypt time: " << decrypt_duration << " ms" << std::endl;
    }

    auto decrypted_from_file = read_file(decrypted_file);
    if (compare_buffers(original, decrypted_from_file)) {
        std::cout << "  File test: OK\n";
    } else {
        std::cout << "  File test: FAILED\n";
    }
}


int main() {
    try {
        fs::path test_dir = "../lb1/test_files";
        if (!fs::exists(test_dir)) {
            std::cerr << "Test directory not found.\n";
            return 1;
        }
        fs::current_path(test_dir);
        std::cout << "Current test directory: " << fs::current_path() << "\n";

        std::vector<std::string> files = { "Homework.docx", "flowers.jpg", "video.mp4" };

        byte_array key_short = {'K', 'e', 'y'};
        byte_array key_long = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 'l', 'o', 'n', 'g', 'e', 'r', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'k', 'e', 'y'};

        for (const auto& file : files) {
            if (fs::exists(file)) {
                try {
                    test_rc4_mode(file, key_short);
                    test_rc4_mode(file, key_long);
                } catch (const std::exception& ex) {
                    std::cerr << "ERROR during test for file " << file << ": " << ex.what() << std::endl;
                }
            }
        }
    } catch (const std::exception& ex) {
        std::cerr << "FATAL ERROR: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}