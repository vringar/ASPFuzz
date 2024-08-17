#!/bin/python

from sys import argv

COLOR_MAPPING = {
    "Black": 30,
    "Red": 31,
    "Green": 32,
    "Yellow": 33,
    "Blue": 34,
    "Magenta": 35,
    "Cyan": 36,
    "White": 37,
}


def colored(text: str, color_code: str) -> str:
    return f"\033[{color_code}m{text}\033[0m"


def pretty_print_bin(bits: str, offset=0,) -> str:
    colors = [
        COLOR_MAPPING["Red"],
        COLOR_MAPPING["Cyan"],
        COLOR_MAPPING["Green"],
        COLOR_MAPPING["Magenta"],
        COLOR_MAPPING["Blue"],
        COLOR_MAPPING["Yellow"],
    ]
    output = ""
    color_index = len(bits) - offset
    for char in bits:
        color_index -= 1
        if color_index >= 0:
            color = colors[(color_index // 4) % len(colors)]
            output += colored(char, color)
        else:
            output += char
        if (color_index + offset) % 4 == 0:
            output += " "
    return output


def show_shifting_bits(number: int, left_shift: int, right_shift: int):
    # Convert the original number to binary representation
    original_bin = bin(number & 0xFFFFFFFF)[2:].zfill(32)  # 32-bit representation

    # Perform the left shift
    left_shifted = (number << left_shift) & 0xFFFFFFFF
    left_shifted_bin = bin(left_shifted)[2:].zfill(32)

    # Perform the right shift
    right_shifted = (left_shifted >> right_shift) & 0xFFFFFFFF
    # Calculate the length of the resulting binary string
    result_length = 32 - left_shift - (right_shift - left_shift)
    right_shifted_bin = bin(right_shifted)[2:].zfill(result_length)

    # Calculate the range of selected bits
    shifted_bit_start = right_shift - left_shift
    shifted_bit_end = 32 - left_shift

    # Print the results
    print(f"Original number (bin):   {pretty_print_bin(original_bin)}")
    print(
        f"After left shift by {left_shift}: {pretty_print_bin(left_shifted_bin, offset=left_shift)}"
    )
    print(
        f"After right shift by {right_shift}: {pretty_print_bin(right_shifted_bin, offset=-shifted_bit_start)}"
    )
    print(f"Final result (dec): {right_shifted}")
    print(f"Selected bits: {shifted_bit_start}:{shifted_bit_end}")
    print(f"Result length: {result_length}")
    return [right_shifted, f"{shifted_bit_start}:{shifted_bit_end}"]


if __name__ == "__main__":
    number = int(argv[1], 0)
    if not (-(2**31) <= number < 2**31):
        raise ValueError("The number must be a 32-bit signed integer.")
    shift_left = int(argv[2], 0)
    shift_right = int(argv[3], 0)
    show_shifting_bits(number, shift_left, shift_right)
    # def number_to_bit_string(number):
    #     return bin(number & 0xFFFFFFFF)[2:].zfill(32)
    # print(pretty_print_bin(number_to_bit_string(0x1230F67f)))
    # print(pretty_print_bin(number_to_bit_string(0x1230F67f), offset=3))