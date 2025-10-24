#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <memory>
#include <chrono>
#include "DES.h"

using namespace DES_Implementation;
namespace fs = std::filesystem;

using byte_array = std::vector<unsigned char>;

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cout << "Cannot open file" << std::endl;
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)), {});
}

bool compare_buffers(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    return a == b;
}

void test_mode(const std::string& file, CipherMode mode, PaddingScheme padding, ExtraParams params = {}) {
    std::cout << "\nTesting file: " << file << " | mode: ";
    switch (mode) {
        case CipherMode::ECB: std::cout << "ECB"; break;
        case CipherMode::CBC: std::cout << "CBC"; break;
        case CipherMode::CFB: std::cout << "CFB"; break;
        case CipherMode::OFB: std::cout << "OFB"; break;
        case CipherMode::CTR: std::cout << "CTR"; break;
        case CipherMode::PCBC: std::cout << "PCBC"; break;
        case CipherMode::RANDOM_DELTA: std::cout << "RANDOM_DELTA"; break;
        default: std::cout << "Other"; break;
    }
    std::cout << std::endl;

    std::vector<unsigned char> key = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 };
    std::vector<unsigned char> iv  = { 0x12,0x34,0x56,0x78,0x90,0xAB,0xCD,0xEF };

    std::vector<unsigned char> original = read_file(file);
    if (original.empty()) {
        std::cout << "Skipped empty file\n";
        return;
    }
    auto des_algo = std::make_unique<DES>();
    CipherContext ctx(std::move(des_algo), key, mode, padding, iv, params);

    std::vector<unsigned char> encrypted;
    ctx.encrypt(original, encrypted).get();

    std::vector<unsigned char> decrypted;
    ctx.decrypt(encrypted, decrypted).get();

    if (compare_buffers(original, decrypted))
        std::cout << "In-memory encryption/decryption OK\n";
    else
        std::cout << "Mismatch after decrypt (in-memory)\n";

    std::string encrypted_file = file + ".enc";
    std::string decrypted_file = file + ".dec";
    auto start_time = std::chrono::high_resolution_clock::now();
    auto end_time = start_time;

    start_time = std::chrono::high_resolution_clock::now();
    ctx.encrypt(file, encrypted_file).get();
    end_time = std::chrono::high_resolution_clock::now();
    auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "  Encrypt time: " << encrypt_duration << " ms" << std::endl;


    start_time = std::chrono::high_resolution_clock::now();
    ctx.decrypt(encrypted_file, decrypted_file).get();
    end_time = std::chrono::high_resolution_clock::now();
    auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "  Decrypt time: " << decrypt_duration << " ms" << std::endl;

    auto decrypted_from_file = read_file(decrypted_file);
    if (compare_buffers(original, decrypted_from_file))
        std::cout << "File encryption/decryption OK\n";
    else
        std::cout << "Mismatch after decrypt (file mode)\n";
}

int main() {
    try {
        fs::path test_dir = "test_files";
        if (!fs::exists(test_dir)) {
            std::cout << "test_files directory not found.\n";
            return 1;
        }
        fs::current_path(test_dir);
        std::cout << "Current directory: " << fs::current_path() << "\n";

        std::vector<std::string> files = {
                "Homework.docx",
                "flowers.jpg",
                "scanner.cpp",
                "video.mp4"
        };

        std::vector<CipherMode> modes = {
                CipherMode::ECB,
                CipherMode::CBC,
                CipherMode::PCBC,
                CipherMode::CFB,
                CipherMode::OFB,
                CipherMode::CTR
        };

        PaddingScheme padding = PaddingScheme::PKCS7;

        for (const auto& file : files) {
            if (!fs::exists(file)) {
                std::cout << "File not found: " << file << std::endl;
                continue;
            }
            for (auto mode : modes) {
                try {
                    test_mode(file, mode, padding);
                }
                catch (const std::exception& ex) {
                    std::cerr << "ERROR during test: " << ex.what() << std::endl;
                }
            }
            ExtraParams delta_params;
            byte_array delta_value = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE};
            delta_params["delta"] = delta_value;
            test_mode(file, CipherMode::RANDOM_DELTA, padding, delta_params);
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
