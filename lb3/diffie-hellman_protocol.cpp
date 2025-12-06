#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>

#include <boost/multiprecision/gmp.hpp>
#include <boost/random.hpp>
#include "Rijndael.h"

using big_int = boost::multiprecision::mpz_int;
using byte_array = std::vector<unsigned char>;

big_int power(big_int base, big_int exp, const big_int& mod) {
    big_int res = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1){
			res = (res * base) % mod;
		}
        base = (base * base) % mod;
        exp /= 2;
    }
    return res;
}


class Party {
private:
    big_int p, g;
    big_int private_key;
    big_int public_key;

public:
    Party(const big_int& p_val, const big_int& g_val) : p(p_val), g(g_val) {
        boost::random::mt19937_64 generator(std::chrono::high_resolution_clock::now().time_since_epoch().count());
        boost::random::uniform_int_distribution<big_int> distribution(2, p - 2);
        private_key = distribution(generator);
        public_key = powm(g, private_key, p);
    }

    big_int getPublicKey() const {
        return public_key;
    }

    big_int generateSharedSecret(const big_int& other_public_key) const {
        return powm(other_public_key, private_key, p);
    }
};

byte_array big_int_to_bytes(const big_int& n) {
    std::string hex_str = n.str(0, std::ios_base::hex);
    if (hex_str.length() % 2 != 0) {
        hex_str = "0" + hex_str;
    }
    byte_array bytes;
    bytes.reserve(hex_str.length() / 2);
    for (size_t i = 0; i < hex_str.length(); i += 2) {
        bytes.push_back(std::stoi(hex_str.substr(i, 2), nullptr, 16));
    }
    return bytes;
}


int main() {
    try {
        std::cout << "--- Diffie-Hellman Key Exchange with Large Numbers ---" << std::endl;

        big_int g = 2;
        big_int p("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                  "DE2BCBF6955817183995497C7EA956AE515D2261898FA0510"
                  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                  "43DB5BFCE0FD108E4B82D120A93AD2CAF FFFFFFFFFFFFFFFF");

        std::cout << "Using 2048-bit prime 'p' and generator 'g=2'" << std::endl;

        Party alice(p, g);
        Party bob(p, g);

        big_int alice_public_key = alice.getPublicKey();
        big_int bob_public_key = bob.getPublicKey();

        std::cout << "\nAlice's public key (first 64 bits): 0x" << std::hex << (alice_public_key >> (2048-64)) << std::endl;
        std::cout << "Bob's public key (first 64 bits):   0x" << std::hex << (bob_public_key >> (2048-64)) << std::endl;

        big_int alice_shared_secret = alice.generateSharedSecret(bob_public_key);
        big_int bob_shared_secret = bob.generateSharedSecret(alice_public_key);

        std::cout << "\nAlice calculates shared secret (first 64 bits): 0x" << std::hex << (alice_shared_secret >> (2048-64)) << std::endl;
        std::cout << "Bob calculates shared secret (first 64 bits):   0x" << std::hex << (bob_shared_secret >> (2048-64)) << std::endl;

        if (alice_shared_secret == bob_shared_secret) {
            std::cout << "\nSuccess! Both parties have the same secret key." << std::endl;
        } else {
            std::cout << "\nFailure! Keys do not match." << std::endl;
            return 1;
        }
        std::cout << "\n--- Using the shared secret with Rijndael (AES-128) ---" << std::endl;
        big_int modulus = 1;
        modulus = modulus << 256;
        big_int key_int = alice_shared_secret % modulus;
        byte_array aes_key = big_int_to_bytes(key_int);
        while (aes_key.size() < 32) {
            aes_key.insert(aes_key.begin(), 0);
        }

        if (aes_key.size() > 32) {
             aes_key.resize(32);
        }

        std::cout << "Generated AES-256 key (Math Modulo method): ";
        for(unsigned char c : aes_key) std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)c;
        std::cout << std::dec << std::endl;
        std::cout << "Key size: " << aes_key.size() << " bytes." << std::endl;
        Rijndael aes(128, 256);

        byte_array plaintext = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 's', 'e', 'c', 'r', 'e', 't'};
        while(plaintext.size() < 16) plaintext.push_back(0);

        aes.setKey(aes_key);
        byte_array ciphertext = aes.encryptBlock(plaintext);

        std::cout << "Ciphertext: ";
        for(auto c : ciphertext) std::cout << std::hex << (int)c << " ";
        std::cout << std::dec << std::endl;

        byte_array decrypted_text = aes.decryptBlock(ciphertext);
        std::cout << "Decrypted text: ";
        for(unsigned char c : decrypted_text) std::cout << c;
        std::cout << std::endl;

        if (plaintext == decrypted_text) {
            std::cout << "\nSuccess! Rijndael encryption/decryption with the shared key works." << std::endl;
        } else {
            std::cout << "\nFailure! Decrypted text does not match original." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "\nAn error occurred: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}