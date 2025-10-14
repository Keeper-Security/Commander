from hashlib import sha3_256, sha3_512, shake_128, shake_256
from .mlkem_math import POLYNOMIAL_DEGREE, FIELD_MODULUS, FiniteFieldElement, KyberPolynomial, RingRepresentation


class CryptographicHashFunctions:
    
    @staticmethod
    def prf(noise_param_eta: int, seed: bytes, counter_bytes: bytes) -> bytes:
        return shake_256(seed + counter_bytes).digest(64 * noise_param_eta)
    
    @staticmethod
    def hash_h(input_bytes: bytes) -> bytes:
        return sha3_256(input_bytes).digest()
    
    @staticmethod
    def hash_j(input_bytes: bytes) -> bytes:
        return shake_256(input_bytes).digest(32)
    
    @staticmethod
    def hash_g(input_bytes: bytes) -> tuple[bytes, bytes]:
        hash_output = sha3_512(input_bytes).digest()
        return hash_output[:32], hash_output[32:]


class ExtendableOutputFunction:
    
    def __init__(self) -> None:
        self.chunk_size = 840
        self.shake = shake_128()
        self.data = b""
        self.idx = 0

    def absorb(self, input_string: bytes) -> None:
        self.shake.update(input_string)
        self.data += self.shake.digest(self.chunk_size)

    def squeeze(self, output_length: int) -> bytes:
        while self.idx + output_length > len(self.data):
            self.data += self.shake.digest(self.chunk_size)
        output_bytes = self.data[self.idx : self.idx + output_length]
        self.idx += output_length
        return output_bytes


class EncodingDecodingUtils:
    
    @staticmethod
    def bits_to_bytes(bit_array: list[int]) -> list[int]:
        bit_array_length = len(bit_array)
        if bit_array_length % 8 != 0:
            raise ValueError(f"Bit array must have a length that is a multiple of 8 (got {bit_array_length}).")
        byte_result = [0 for _ in range(bit_array_length // 8)]
        for bit_index in range(bit_array_length):
            bit_value = bit_array[bit_index] * (1 << (bit_index % 8))
            byte_result[bit_index // 8] = byte_result[bit_index // 8] + bit_value
        return byte_result

    @staticmethod
    def bytes_to_bits(byte_array: list[int]) -> list[int]:
        byte_copy = byte_array.copy()
        bit_result: list[int] = []
        for byte_index in range(len(byte_copy)):
            for _ in range(8):
                bit_result.append(byte_copy[byte_index] & 1)
                byte_copy[byte_index] //= 2
        return bit_result

    @staticmethod
    def _round_fraction(numerator: int, denominator: int) -> int:
        return (2 * numerator + denominator) // (2 * denominator)

    @staticmethod
    def compress(bits_per_coeff: int, field_element: FiniteFieldElement) -> FiniteFieldElement:
        if not bits_per_coeff < FIELD_MODULUS.bit_length():
            raise ValueError(f"bits_per_coeff must be less than {FIELD_MODULUS.bit_length()} (got {bits_per_coeff}).")
        if field_element.modulus != FIELD_MODULUS:
            raise ValueError(f"Element being compressed must be in Z_q (got Z_{field_element.modulus}).")
        compression_modulus = 1 << bits_per_coeff
        compressed_value = EncodingDecodingUtils._round_fraction(compression_modulus * field_element.element_value, FIELD_MODULUS) % compression_modulus
        return FiniteFieldElement(compressed_value, compression_modulus)

    @staticmethod
    def decompress(bits_per_coeff: int, compressed_element: FiniteFieldElement) -> FiniteFieldElement:
        if not bits_per_coeff < FIELD_MODULUS.bit_length():
            raise ValueError(f"bits_per_coeff must be less than {FIELD_MODULUS.bit_length()} (got {bits_per_coeff}).")
        compression_modulus = 1 << bits_per_coeff
        decompressed_value = EncodingDecodingUtils._round_fraction(FIELD_MODULUS * compressed_element.element_value, compression_modulus)
        return FiniteFieldElement(decompressed_value, FIELD_MODULUS)

    @staticmethod
    def byte_encode(bits_per_coeff: int, coefficient_list: list[FiniteFieldElement]) -> bytes:
        if len(coefficient_list) != POLYNOMIAL_DEGREE:
            raise ValueError(f"Expected {POLYNOMIAL_DEGREE} coefficients (got {len(coefficient_list)}).")
        if not bits_per_coeff < FIELD_MODULUS.bit_length():
            raise ValueError(f"bits_per_coeff must be less than {FIELD_MODULUS.bit_length()} (got {bits_per_coeff}).")
        
        bit_array = []
        for coeff in coefficient_list:
            if coeff.modulus != (1 << bits_per_coeff):
                raise ValueError(f"All coefficients must be in Z_{{2^bits_per_coeff}} (got Z_{coeff.modulus}).")
            for bit_position in range(bits_per_coeff):
                bit_array.append((coeff.element_value >> bit_position) & 1)
        
        return bytes(EncodingDecodingUtils.bits_to_bytes(bit_array))

    @staticmethod
    def byte_decode(bits_per_coeff: int, byte_data: bytes) -> list[FiniteFieldElement]:
        if len(byte_data) != 32 * bits_per_coeff:
            raise ValueError(f"Expected {32 * bits_per_coeff} bytes (got {len(byte_data)}).")
        if not bits_per_coeff < FIELD_MODULUS.bit_length():
            raise ValueError(f"bits_per_coeff must be less than {FIELD_MODULUS.bit_length()} (got {bits_per_coeff}).")
        
        bit_array = EncodingDecodingUtils.bytes_to_bits(list(byte_data))
        coefficient_result = []
        for coeff_index in range(POLYNOMIAL_DEGREE):
            coefficient_value = 0
            for bit_position in range(bits_per_coeff):
                coefficient_value += bit_array[coeff_index * bits_per_coeff + bit_position] * (1 << bit_position)
            coefficient_result.append(FiniteFieldElement(coefficient_value, 1 << bits_per_coeff))
        
        return coefficient_result


class NumberTheoreticTransform:
    
    ZETA_LOOKUP = [
        FiniteFieldElement(x, FIELD_MODULUS) for x in [
            1, 1729, 2580, 3289, 2642, 630, 1897, 848,
            1062, 1919, 193, 797, 2786, 3260, 569, 1746,
            296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
            1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
            289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
            650, 1977, 2513, 632, 2865, 33, 1320, 1915,
            2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
            2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
            17, 2761, 583, 2649, 1637, 723, 2288, 1100,
            1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
            1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
            939, 2308, 2437, 2388, 733, 2337, 268, 641,
            1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
            1063, 319, 2773, 757, 2099, 561, 2466, 2594,
            2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
            1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
        ]
    ]

    GAMMA_LOOKUP = [
        FiniteFieldElement(x, FIELD_MODULUS) for x in [
            17, -17, 2761, -2761, 583, -583, 2649, -2649,
            1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
            1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
            756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
            1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
            1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
            939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
            733, -733, 2337, -2337, 268, -268, 641, -641,
            1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
            375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
            1063, -1063, 319, -319, 2773, -2773, 757, -757,
            2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
            2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
            1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
            1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
            2110, -2110, 2935, -2935, 885, -885, 2154, -2154
        ]
    ]

    @staticmethod
    def forward_transform(polynomial: KyberPolynomial) -> KyberPolynomial:
        if polynomial.representation != RingRepresentation.STANDARD:
            raise ValueError(f"Input must be in standard representation, got {polynomial.representation}")
        ntt_polynomial = KyberPolynomial([polynomial[coeff_idx] for coeff_idx in range(POLYNOMIAL_DEGREE)], RingRepresentation.NTT)
        transform_length = 128
        for transform_length in [128, 64, 32, 16, 8, 4, 2]:
            for block_start in range(0, POLYNOMIAL_DEGREE, 2 * transform_length):
                twiddle_factor = NumberTheoreticTransform.ZETA_LOOKUP[128 // transform_length]
                for coeff_idx in range(block_start, block_start + transform_length):
                    temp_value = twiddle_factor * ntt_polynomial[coeff_idx + transform_length]
                    ntt_polynomial[coeff_idx + transform_length] = ntt_polynomial[coeff_idx] - temp_value
                    ntt_polynomial[coeff_idx] = ntt_polynomial[coeff_idx] + temp_value
        return ntt_polynomial

    @staticmethod
    def inverse_transform(ntt_polynomial: KyberPolynomial) -> KyberPolynomial:
        if ntt_polynomial.representation != RingRepresentation.NTT:
            raise ValueError(f"Input must be in NTT representation, got {ntt_polynomial.representation}")
        standard_polynomial = KyberPolynomial([ntt_polynomial[coeff_idx] for coeff_idx in range(POLYNOMIAL_DEGREE)], RingRepresentation.STANDARD)
        transform_length = 2
        for transform_length in [2, 4, 8, 16, 32, 64, 128]:
            for block_start in range(0, POLYNOMIAL_DEGREE, 2 * transform_length):
                twiddle_factor = NumberTheoreticTransform.ZETA_LOOKUP[128 // transform_length]
                for coeff_idx in range(block_start, block_start + transform_length):
                    temp_value = standard_polynomial[coeff_idx]
                    standard_polynomial[coeff_idx] = temp_value + standard_polynomial[coeff_idx + transform_length]
                    standard_polynomial[coeff_idx + transform_length] = twiddle_factor * (standard_polynomial[coeff_idx + transform_length] - temp_value)
        for coeff_idx in range(POLYNOMIAL_DEGREE):
            standard_polynomial[coeff_idx] = standard_polynomial[coeff_idx] * FiniteFieldElement(3303, FIELD_MODULUS)
        return standard_polynomial

    @staticmethod
    def multiply_in_ntt_domain(first_ntt_poly: KyberPolynomial, second_ntt_poly: KyberPolynomial) -> KyberPolynomial:
        if first_ntt_poly.representation != RingRepresentation.NTT or second_ntt_poly.representation != RingRepresentation.NTT:
            raise ValueError("Both inputs must be in NTT representation")
        product_ntt_poly = KyberPolynomial(representation=RingRepresentation.NTT)
        for pair_idx in range(POLYNOMIAL_DEGREE // 2):
            first_even, first_odd = first_ntt_poly[2 * pair_idx], first_ntt_poly[2 * pair_idx + 1]
            second_even, second_odd = second_ntt_poly[2 * pair_idx], second_ntt_poly[2 * pair_idx + 1]
            gamma_factor = NumberTheoreticTransform.GAMMA_LOOKUP[pair_idx]
            product_even, product_odd = NumberTheoreticTransform._base_case_multiply(first_even, first_odd, second_even, second_odd, gamma_factor)
            product_ntt_poly[2 * pair_idx] = product_even
            product_ntt_poly[2 * pair_idx + 1] = product_odd
        return product_ntt_poly

    @staticmethod
    def _base_case_multiply(first_even: FiniteFieldElement, first_odd: FiniteFieldElement, second_even: FiniteFieldElement, second_odd: FiniteFieldElement, gamma_factor: FiniteFieldElement) -> tuple[FiniteFieldElement, FiniteFieldElement]:
        product_even = first_even * second_even + first_odd * second_odd * gamma_factor
        product_odd = first_even * second_odd + first_odd * second_even
        return product_even, product_odd


class PolynomialSampler:
    
    @staticmethod
    def sample_ntt_polynomial(seed_bytes: bytes) -> KyberPolynomial:
        if len(seed_bytes) != 34:
            raise ValueError(f"Input must be 34 bytes (32-byte seed and two indices). Got {len(seed_bytes)}.")
        ntt_polynomial = KyberPolynomial(representation=RingRepresentation.NTT)
        extendable_output = ExtendableOutputFunction()
        extendable_output.absorb(seed_bytes)
        coefficient_count = 0
        while coefficient_count < POLYNOMIAL_DEGREE:
            random_bytes = extendable_output.squeeze(3)
            candidate_1 = random_bytes[0] + POLYNOMIAL_DEGREE * (random_bytes[1] % 16)
            candidate_2 = random_bytes[1] // 16 + 16 * random_bytes[2]
            if candidate_1 < FIELD_MODULUS:
                ntt_polynomial[coefficient_count] = FiniteFieldElement(candidate_1, FIELD_MODULUS)
                coefficient_count += 1
            if candidate_2 < FIELD_MODULUS and coefficient_count < POLYNOMIAL_DEGREE:
                ntt_polynomial[coefficient_count] = FiniteFieldElement(candidate_2, FIELD_MODULUS)
                coefficient_count += 1
        return ntt_polynomial

    @staticmethod
    def sample_centered_binomial_polynomial(noise_param_eta: int, random_bytes: bytes) -> KyberPolynomial:
        if noise_param_eta not in {2, 3}:
            raise ValueError(f"noise_param_eta must be 2 or 3, got {noise_param_eta}")
        if len(random_bytes) != 64 * noise_param_eta:
            raise ValueError(f"Input must be {64 * noise_param_eta} bytes, got {len(random_bytes)}")
        bit_array = EncodingDecodingUtils.bytes_to_bits(list(random_bytes))
        cbd_polynomial = KyberPolynomial()
        for coeff_idx in range(POLYNOMIAL_DEGREE):
            positive_sum = sum(bit_array[2 * coeff_idx * noise_param_eta + bit_pos] for bit_pos in range(noise_param_eta))
            negative_sum = sum(bit_array[2 * coeff_idx * noise_param_eta + noise_param_eta + bit_pos] for bit_pos in range(noise_param_eta))
            cbd_polynomial[coeff_idx] = FiniteFieldElement(positive_sum - negative_sum, FIELD_MODULUS)
        return cbd_polynomial