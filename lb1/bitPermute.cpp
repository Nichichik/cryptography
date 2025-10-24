//
// Created by Вероника on 01.10.2025.
//

#include "bitPermute.h"
#include<iostream>
#include <vector>


std::vector<unsigned char> permute(
        const std::vector<unsigned char>& input,
        const std::vector<int>& p_block,
        BitDir direction,
        BitBase base
) {
    if (input.empty() || p_block.empty()) {
        std::cout<<"Input data and P-block cannot be empty."<< std::endl;
    }

    const size_t input_bits_count = input.size() * 8;
    const size_t output_bits_count = p_block.size();

    if (output_bits_count % 8 != 0) {
        std::cout<<"P-block size (output bit count) must be a multiple of 8."<< std::endl;
    }

    std::vector<unsigned char> output(output_bits_count / 8, 0);

    std::vector<bool> temp_bits(output_bits_count);

    for (size_t i = 0; i < output_bits_count; ++i) {
        int source_bit_index = p_block[i];
        if (base == BitBase::ONE_BASE) {
            source_bit_index--;
        }

        if (source_bit_index < 0 || source_bit_index >= input_bits_count) {
            std::cout<<"P-block index is out of input data range."<< std::endl;
        }

        size_t source_byte_idx = source_bit_index / 8;
        size_t bit_pos_in_byte = source_bit_index % 8;

        size_t shift = (direction == BitDir::BIG_END) ? (7 - bit_pos_in_byte) : bit_pos_in_byte;

        temp_bits[i] = ((input[source_byte_idx] >> shift) & 1);
    }

    for (size_t i = 0; i < output_bits_count; ++i) {
        if (temp_bits[i]) {
            size_t dest_byte_idx = i / 8;
            size_t dest_bit_in_byte = i % 8;
            output[dest_byte_idx] |= (1 << (7 - dest_bit_in_byte));
        }
    }

    return output;
}
