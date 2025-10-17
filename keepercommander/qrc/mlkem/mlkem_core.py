from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import reduce
from hashlib import shake_128
from os import urandom
from .mlkem_auxiliary import CryptographicHashFunctions, EncodingDecodingUtils, NumberTheoreticTransform, PolynomialSampler
from .mlkem_math import FiniteFieldElement, PolynomialMatrix, KyberPolynomial, RingRepresentation

@dataclass
class MLKEMParameterSet:
    security_level_dimension: int
    noise_parameter_eta1: int
    noise_parameter_eta2: int
    compression_bits_u: int
    compression_bits_v: int

MLKEM_512_PARAMETERS = MLKEMParameterSet(2, 3, 2, 10, 4)
MLKEM_768_PARAMETERS = MLKEMParameterSet(3, 2, 2, 10, 4)
MLKEM_1024_PARAMETERS = MLKEMParameterSet(4, 2, 2, 11, 5)

class PublicKeyEncryptionInterface(ABC):
    @abstractmethod
    def key_gen(self, seed: bytes) -> tuple[bytes, bytes]: pass
    @abstractmethod
    def encrypt(self, encapsulation_key: bytes, message: bytes, randomness: bytes) -> bytes: pass
    @abstractmethod
    def decrypt(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes: pass

class StandardMLKEMImplementation(PublicKeyEncryptionInterface):
    def __init__(self, parameters: MLKEMParameterSet):
        self.parameters = parameters

    def key_gen(self, seed: bytes) -> tuple[bytes, bytes]:
        k, eta1 = self.parameters.security_level_dimension, self.parameters.noise_parameter_eta1
        public_seed, private_seed = CryptographicHashFunctions.hash_g(seed + bytes([k]))
        matrix_a_ntt = self._generate_matrix_a(public_seed)
        secret_vector, counter = self._sample_column_vector(eta1, private_seed, 0)
        error_vector, _ = self._sample_column_vector(eta1, private_seed, counter)
        secret_vector_ntt = secret_vector.map(NumberTheoreticTransform.forward_transform)
        error_vector_ntt = error_vector.map(NumberTheoreticTransform.forward_transform)
        public_vector_t_ntt = matrix_a_ntt * secret_vector_ntt + error_vector_ntt
        encapsulation_key = reduce(lambda b, p: b + EncodingDecodingUtils.byte_encode(12, p.coefficients), public_vector_t_ntt.entries, b"") + public_seed
        decapsulation_key = reduce(lambda b, p: b + EncodingDecodingUtils.byte_encode(12, p.coefficients), secret_vector_ntt.entries, b"")
        return encapsulation_key, decapsulation_key

    def encrypt(self, encapsulation_key: bytes, message: bytes, randomness: bytes) -> bytes:
        k, du, dv = self.parameters.security_level_dimension, self.parameters.compression_bits_u, self.parameters.compression_bits_v
        public_vector_t_ntt = self._bytes_to_column_vector(encapsulation_key[:384*k], RingRepresentation.NTT, 12)
        public_seed = encapsulation_key[384*k:384*k+32]
        matrix_a_ntt = self._generate_matrix_a(public_seed)
        random_vector_y, counter = self._sample_column_vector(self.parameters.noise_parameter_eta1, randomness, 0)
        error_vector_e1, counter = self._sample_column_vector(self.parameters.noise_parameter_eta2, randomness, counter)
        error_scalar_e2 = PolynomialSampler.sample_centered_binomial_polynomial(self.parameters.noise_parameter_eta2, CryptographicHashFunctions.prf(self.parameters.noise_parameter_eta2, randomness, bytes([counter])))
        random_vector_y_ntt = random_vector_y.map(NumberTheoreticTransform.forward_transform)
        ciphertext_u = (matrix_a_ntt.transpose() * random_vector_y_ntt).map(NumberTheoreticTransform.inverse_transform) + error_vector_e1
        message_polynomial = KyberPolynomial([EncodingDecodingUtils.decompress(1, c) for c in EncodingDecodingUtils.byte_decode(1, message)], RingRepresentation.STANDARD)
        ciphertext_v = NumberTheoreticTransform.inverse_transform((public_vector_t_ntt.transpose() * random_vector_y_ntt).get_singleton_element()) + error_scalar_e2 + message_polynomial
        compressed_u_coeffs = reduce(lambda l, p: l + [[EncodingDecodingUtils.compress(du, c) for c in p.coefficients]], ciphertext_u.entries, [])
        ciphertext_c1 = reduce(lambda b, c: b + EncodingDecodingUtils.byte_encode(du, c), compressed_u_coeffs, b"")
        ciphertext_c2 = EncodingDecodingUtils.byte_encode(dv, [EncodingDecodingUtils.compress(dv, c) for c in ciphertext_v.coefficients])
        return ciphertext_c1 + ciphertext_c2

    def decrypt(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        du, dv, k = self.parameters.compression_bits_u, self.parameters.compression_bits_v, self.parameters.security_level_dimension
        ciphertext_c1, ciphertext_c2 = ciphertext[:32*du*k], ciphertext[32*du*k:32*(du*k+dv)]
        decoded_u = self._bytes_to_column_vector(ciphertext_c1, RingRepresentation.STANDARD, du, True)
        decoded_v = KyberPolynomial([EncodingDecodingUtils.decompress(dv, c) for c in EncodingDecodingUtils.byte_decode(dv, ciphertext_c2)], RingRepresentation.STANDARD)
        secret_vector_ntt = self._bytes_to_column_vector(decapsulation_key, RingRepresentation.NTT, 12)
        recovered_message_poly = decoded_v - NumberTheoreticTransform.inverse_transform((secret_vector_ntt.transpose() * decoded_u.map(NumberTheoreticTransform.forward_transform)).get_singleton_element())
        return EncodingDecodingUtils.byte_encode(1, [EncodingDecodingUtils.compress(1, c) for c in recovered_message_poly.coefficients])

    def _generate_matrix_a(self, public_seed: bytes) -> PolynomialMatrix[KyberPolynomial]:
        k = self.parameters.security_level_dimension
        matrix_a_ntt = PolynomialMatrix(k, k, constructor=lambda: KyberPolynomial(representation=RingRepresentation.NTT))
        for i in range(k):
            for j in range(k):
                matrix_a_ntt[(i, j)] = PolynomialSampler.sample_ntt_polynomial(public_seed + bytes([j, i]))
        return matrix_a_ntt

    def _sample_column_vector(self, eta: int, randomness: bytes, counter: int) -> tuple[PolynomialMatrix[KyberPolynomial], int]:
        k = self.parameters.security_level_dimension
        column_vector = PolynomialMatrix(k, 1, constructor=lambda: KyberPolynomial(representation=RingRepresentation.STANDARD))
        for i in range(k):
            prf_seed = CryptographicHashFunctions.prf(eta, randomness, bytes([counter]))
            column_vector[(i, 0)] = PolynomialSampler.sample_centered_binomial_polynomial(eta, prf_seed)
            counter += 1
        return column_vector, counter

    def _bytes_to_column_vector(self, byte_data: bytes, representation: RingRepresentation, bits_per_coeff: int, compressed: bool = False) -> PolynomialMatrix[KyberPolynomial]:
        k, bytes_per_poly = self.parameters.security_level_dimension, 32 * bits_per_coeff
        return PolynomialMatrix(k, 1, entries=[
            KyberPolynomial([EncodingDecodingUtils.decompress(bits_per_coeff, c) for c in EncodingDecodingUtils.byte_decode(bits_per_coeff, byte_data[i:i+bytes_per_poly])] if compressed else EncodingDecodingUtils.byte_decode(bits_per_coeff, byte_data[i:i+bytes_per_poly]), representation)
            for i in range(0, bytes_per_poly * k, bytes_per_poly)
        ])

class OptimizedMLKEMImplementation(PublicKeyEncryptionInterface):
    def __init__(self, parameters: MLKEMParameterSet):
        self.parameters = parameters

    def key_gen(self, seed: bytes) -> tuple[bytes, bytes]:
        try:
            from .fastmath import add_matrix, byte_encode_matrix, map_ntt_matrix, mul_matrix
        except ImportError:
            raise ImportError("Fast math C extension not available. Use StandardMLKEMImplementation instead.")
        k = self.parameters.security_level_dimension
        public_seed, private_seed = CryptographicHashFunctions.hash_g(seed + bytes([k]))
        matrix_a_ntt = self._generate_matrix_a_optimized(public_seed)
        secret_vector = self._sample_column_vector_optimized(self.parameters.noise_parameter_eta1, private_seed, 0)
        error_vector = self._sample_column_vector_optimized(self.parameters.noise_parameter_eta1, private_seed, k)
        secret_vector_ntt, error_vector_ntt = map_ntt_matrix(secret_vector), map_ntt_matrix(error_vector)
        public_vector_t_ntt = add_matrix(mul_matrix(matrix_a_ntt, secret_vector_ntt, k, k, k, 1), error_vector_ntt)
        return byte_encode_matrix(public_vector_t_ntt, 12) + public_seed, byte_encode_matrix(secret_vector_ntt, 12)

    def encrypt(self, encapsulation_key: bytes, message: bytes, randomness: bytes) -> bytes:
        try:
            from .fastmath import add_matrix, add_poly, byte_decode_matrix, byte_decode_poly, byte_encode_matrix, byte_encode_poly, compress_matrix, compress_poly, decompress_poly, map_ntt_inv_matrix, map_ntt_matrix, mul_matrix, ntt_inv, sample_poly_cbd
        except ImportError:
            raise ImportError("Fast math C extension not available. Use StandardMLKEMImplementation instead.")
        k, du, dv = self.parameters.security_level_dimension, self.parameters.compression_bits_u, self.parameters.compression_bits_v
        public_vector_t_ntt = byte_decode_matrix(encapsulation_key[:384*k], 12, k)
        public_seed = encapsulation_key[384*k:384*k+32]
        matrix_a_ntt = self._generate_matrix_a_optimized(public_seed)
        random_vector_y = self._sample_column_vector_optimized(self.parameters.noise_parameter_eta1, randomness, 0)
        error_vector_e1 = self._sample_column_vector_optimized(self.parameters.noise_parameter_eta2, randomness, k)
        error_scalar_e2 = sample_poly_cbd(CryptographicHashFunctions.prf(self.parameters.noise_parameter_eta2, randomness, bytes([2*k])), self.parameters.noise_parameter_eta2)
        random_vector_y_ntt = map_ntt_matrix(random_vector_y)
        ciphertext_u = add_matrix(map_ntt_inv_matrix(mul_matrix(self._transpose_matrix(matrix_a_ntt, k, k), random_vector_y_ntt, k, k, k, 1)), error_vector_e1)
        message_polynomial = decompress_poly(byte_decode_poly(message, 1), 1)
        t_y_result = ntt_inv(mul_matrix(self._transpose_matrix(public_vector_t_ntt, k, 1), random_vector_y_ntt, 1, k, k, 1)[0])
        ciphertext_v = add_poly(add_poly(t_y_result, error_scalar_e2), message_polynomial)
        return byte_encode_matrix(compress_matrix(ciphertext_u, du), du) + byte_encode_poly(compress_poly(ciphertext_v, dv), dv)

    def decrypt(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        try:
            from .fastmath import byte_decode_matrix, byte_decode_poly, byte_encode_poly, compress_poly, decompress_matrix, decompress_poly, map_ntt_matrix, mul_matrix, ntt_inv, sub_poly
        except ImportError:
            raise ImportError("Fast math C extension not available. Use StandardMLKEMImplementation instead.")
        du, dv, k = self.parameters.compression_bits_u, self.parameters.compression_bits_v, self.parameters.security_level_dimension
        ciphertext_c1, ciphertext_c2 = ciphertext[:32*du*k], ciphertext[32*du*k:32*(du*k+dv)]
        decoded_u, decoded_v = decompress_matrix(byte_decode_matrix(ciphertext_c1, du, k), du), decompress_poly(byte_decode_poly(ciphertext_c2, dv), dv)
        secret_vector_ntt = byte_decode_matrix(decapsulation_key, 12, k)
        secret_times_u = mul_matrix(self._transpose_matrix(secret_vector_ntt, k, 1), map_ntt_matrix(decoded_u), 1, k, k, 1)
        recovered_message_poly = sub_poly(decoded_v, ntt_inv(secret_times_u[0]))
        return byte_encode_poly(compress_poly(recovered_message_poly, 1), 1)

    def _generate_matrix_a_optimized(self, public_seed: bytes) -> list[list[int]]:
        try:
            from .fastmath import sample_ntt
        except ImportError:
            raise ImportError("Fast math C extension not available. Use StandardMLKEMImplementation instead.")
        k, matrix_elements = self.parameters.security_level_dimension, []
        for i in range(k):
            for j in range(k):
                xof_hasher = shake_128()
                xof_hasher.update(public_seed + bytes([j, i]))
                matrix_elements.append(sample_ntt(xof_hasher.digest(840)))
        return matrix_elements

    def _sample_column_vector_optimized(self, eta: int, randomness: bytes, counter: int) -> list[list[int]]:
        try:
            from .fastmath import sample_poly_cbd
        except ImportError:
            raise ImportError("Fast math C extension not available. Use StandardMLKEMImplementation instead.")
        column_vector = []
        for _ in range(self.parameters.security_level_dimension):
            prf_seed = CryptographicHashFunctions.prf(eta, randomness, bytes([counter]))
            column_vector.append(sample_poly_cbd(prf_seed, eta))
            counter += 1
        return column_vector

    def _transpose_matrix(self, matrix: list[list[int]], rows: int, cols: int) -> list[list[int]]:
        transposed = [[] for _ in range(rows * cols)]
        for i in range(rows):
            for j in range(cols):
                transposed[j * rows + i] = matrix[i * cols + j]
        return transposed

class ML_KEM:
    def __init__(self, parameters: MLKEMParameterSet = MLKEM_768_PARAMETERS, fast: bool = True):
        self.parameters, self.fast = parameters, fast
        if fast:
            try:
                self.k_pke = OptimizedMLKEMImplementation(parameters)
            except ImportError:
                self.fast = False
        if not self.fast:
            self.k_pke = StandardMLKEMImplementation(parameters)

    def key_gen(self) -> tuple[bytes, bytes]:
        return self._key_gen(urandom(32), urandom(32))

    def encaps(self, encapsulation_key: bytes) -> tuple[bytes, bytes]:
        k = self.parameters.security_level_dimension
        expected_key_length = 384 * k + 32
        if len(encapsulation_key) != expected_key_length:
            raise ValueError(f"Invalid encapsulation key length: {len(encapsulation_key)} (expected {expected_key_length})")
        if self.fast:
            try:
                from .fastmath import byte_decode_matrix, byte_encode_matrix
                expected_key_bytes = encapsulation_key[:384 * k]
                validation_test = byte_encode_matrix(byte_decode_matrix(encapsulation_key, 12, k), 12)
                if expected_key_bytes != validation_test:
                    raise ValueError("Encapsulation key contains invalid coefficients")
            except ImportError:
                pass
        return self._encaps(encapsulation_key, urandom(32))

    def decaps(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        k, du, dv = self.parameters.security_level_dimension, self.parameters.compression_bits_u, self.parameters.compression_bits_v
        expected_decaps_key_length, expected_ciphertext_length = 768 * k + 96, 32 * (du * k + dv)
        if len(decapsulation_key) != expected_decaps_key_length:
            raise ValueError(f"Invalid decapsulation key length: {len(decapsulation_key)} (expected {expected_decaps_key_length})")
        if len(ciphertext) != expected_ciphertext_length:
            raise ValueError(f"Invalid ciphertext length: {len(ciphertext)} (expected {expected_ciphertext_length})")
        embedded_encaps_key = decapsulation_key[384 * k : 768 * k + 32]
        stored_hash = decapsulation_key[768 * k + 32 : 768 * k + 64]
        if CryptographicHashFunctions.hash_h(embedded_encaps_key) != stored_hash:
            raise ValueError("Encapsulation key hash verification failed")
        return self._decaps(decapsulation_key, ciphertext)

    def _key_gen(self, key_generation_seed: bytes, implicit_rejection_value: bytes) -> tuple[bytes, bytes]:
        encapsulation_key, pke_decapsulation_key = self.k_pke.key_gen(key_generation_seed)
        full_decapsulation_key = pke_decapsulation_key + encapsulation_key + CryptographicHashFunctions.hash_h(encapsulation_key) + implicit_rejection_value
        return encapsulation_key, full_decapsulation_key

    def _encaps(self, encapsulation_key: bytes, random_message: bytes) -> tuple[bytes, bytes]:
        shared_secret, encryption_randomness = CryptographicHashFunctions.hash_g(random_message + CryptographicHashFunctions.hash_h(encapsulation_key))
        ciphertext = self.k_pke.encrypt(encapsulation_key, random_message, encryption_randomness)
        return shared_secret, ciphertext

    def _decaps(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        k = self.parameters.security_level_dimension
        pke_decapsulation_key = decapsulation_key[:384 * k]
        embedded_encaps_key = decapsulation_key[384 * k : 384 * k + 32 + 384 * k]
        stored_encaps_key_hash = decapsulation_key[384 * k + 32 + 384 * k : 384 * k + 32 + 384 * k + 32]
        implicit_rejection_value = decapsulation_key[384 * k + 32 + 384 * k + 32 :]
        decrypted_message = self.k_pke.decrypt(pke_decapsulation_key, ciphertext)
        derived_shared_secret, derived_randomness = CryptographicHashFunctions.hash_g(decrypted_message + stored_encaps_key_hash)
        implicit_rejection_secret = CryptographicHashFunctions.hash_j(implicit_rejection_value + ciphertext)
        if ciphertext == self.k_pke.encrypt(embedded_encaps_key, decrypted_message, derived_randomness):
            return derived_shared_secret
        else:
            return implicit_rejection_secret