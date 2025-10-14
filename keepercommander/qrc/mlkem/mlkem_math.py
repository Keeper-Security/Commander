from __future__ import annotations
from enum import Enum
from typing import Callable, Generic, TypeVar

POLYNOMIAL_DEGREE: int = 256
FIELD_MODULUS: int = 3329

T = TypeVar("T")


class FiniteFieldElement:
    element_value: int

    def __init__(self, value: int, modulus: int):
        self.modulus = modulus
        self.element_value = value % modulus

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FiniteFieldElement):
            return NotImplemented
        return self.modulus == other.modulus and self.element_value == other.element_value

    def __repr__(self) -> str:
        return f"{self.element_value}"

    def __add__(self, other_element: FiniteFieldElement) -> FiniteFieldElement:
        if self.modulus != other_element.modulus:
            raise ValueError(f"Cannot add elements from different rings: Z_{self.modulus} and Z_{other_element.modulus}.")
        return FiniteFieldElement(self.element_value + other_element.element_value, self.modulus)

    def __sub__(self, other_element: FiniteFieldElement) -> FiniteFieldElement:
        if self.modulus != other_element.modulus:
            raise ValueError(f"Cannot subtract elements from different rings: Z_{self.modulus} and Z_{other_element.modulus}.")
        return FiniteFieldElement(self.element_value - other_element.element_value, self.modulus)

    def __mul__(self, other_element: FiniteFieldElement) -> FiniteFieldElement:
        if self.modulus != other_element.modulus:
            raise ValueError(f"Cannot multiply elements from different rings: Z_{self.modulus} and Z_{other_element.modulus}.")
        return FiniteFieldElement(self.element_value * other_element.element_value, self.modulus)


class PolynomialMatrix(Generic[T]):
    rows: int
    cols: int
    entries: list[T]

    def __init__(self, rows: int, cols: int, entries: list[T] | None = None, constructor: Callable[[], T] | None = None) -> None:
        self.rows = rows
        self.cols = cols
        if entries is not None:
            assert len(entries) == rows * cols, f"Entries had {len(entries)} entries, expected {rows} * {cols} entries."
            self.entries = entries
        elif constructor is not None:
            self.entries = [constructor() for _ in range(rows * cols)]
        else:
            raise ValueError("Must provide either entries or constructor")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PolynomialMatrix):
            return NotImplemented
        if self.rows != other.rows or self.cols != other.cols:
            return False
        return all([entry_self == entry_other for (entry_self, entry_other) in zip(self.entries, other.entries)])

    def __repr__(self) -> str:
        matrix_repr = "[ "
        matrix_repr += ", ".join([
            "[ " + ", ".join([repr(self[(row_idx, col_idx)]) for col_idx in range(self.cols)]) + " ]"
            for row_idx in range(self.rows)
        ])
        matrix_repr += " ]"
        return matrix_repr

    def __getitem__(self, index: tuple[int, int]) -> T:
        row_idx, col_idx = index
        if not (0 <= row_idx < self.rows):
            raise IndexError(f"Row index {row_idx} out of bounds for matrix with {self.rows} rows.")
        if not (0 <= col_idx < self.cols):
            raise IndexError(f"Column index {col_idx} out of bounds for matrix with {self.cols} columns.")
        return self.entries[row_idx * self.cols + col_idx]

    def __setitem__(self, index: tuple[int, int], value: T) -> None:
        row_idx, col_idx = index
        if not (0 <= row_idx < self.rows):
            raise IndexError(f"Row index {row_idx} out of bounds for matrix with {self.rows} rows.")
        if not (0 <= col_idx < self.cols):
            raise IndexError(f"Column index {col_idx} out of bounds for matrix with {self.cols} columns.")
        self.entries[row_idx * self.cols + col_idx] = value

    def __add__(self, other: PolynomialMatrix[T]) -> PolynomialMatrix[T]:
        if self.rows != other.rows or self.cols != other.cols:
            raise ValueError(f"Cannot add matrices of different dimensions: {self.rows}x{self.cols} and {other.rows}x{other.cols}.")
        return PolynomialMatrix(self.rows, self.cols, [entry_self + entry_other for (entry_self, entry_other) in zip(self.entries, other.entries)])

    def __mul__(self, other_matrix_or_scalar: T | PolynomialMatrix[T]) -> PolynomialMatrix[T]:
        if isinstance(other_matrix_or_scalar, PolynomialMatrix):
            if self.cols != other_matrix_or_scalar.rows:
                raise ValueError(f"Cannot multiply matrices: {self.rows}x{self.cols} and {other_matrix_or_scalar.rows}x{other_matrix_or_scalar.cols}.")
            product_matrix = PolynomialMatrix(self.rows, other_matrix_or_scalar.cols, constructor=lambda: self.entries[0] * other_matrix_or_scalar.entries[0] - self.entries[0] * other_matrix_or_scalar.entries[0])
            for row_idx in range(self.rows):
                for col_idx in range(other_matrix_or_scalar.cols):
                    product_matrix[(row_idx, col_idx)] = sum([self[(row_idx, inner_idx)] * other_matrix_or_scalar[(inner_idx, col_idx)] for inner_idx in range(self.cols)], product_matrix[(row_idx, col_idx)])
            return product_matrix
        else:
            return PolynomialMatrix(self.rows, self.cols, [entry * other_matrix_or_scalar for entry in self.entries])

    def map(self, transform_function: Callable[[T], T]) -> PolynomialMatrix[T]:
        return PolynomialMatrix(self.rows, self.cols, [transform_function(entry) for entry in self.entries])

    def transpose(self) -> PolynomialMatrix[T]:
        transposed_matrix = PolynomialMatrix(self.cols, self.rows, constructor=lambda: self.entries[0])
        for row_idx in range(self.rows):
            for col_idx in range(self.cols):
                transposed_matrix[(col_idx, row_idx)] = self[(row_idx, col_idx)]
        return transposed_matrix

    def get_singleton_element(self) -> T:
        if self.rows != 1 or self.cols != 1:
            raise ValueError(f"Cannot get singleton element from {self.rows}x{self.cols} matrix.")
        return self[(0, 0)]


class RingRepresentation(Enum):
    STANDARD = "Standard Polynomial Ring (Rq)"
    NTT = "NTT Representation (Tq)"


class KyberPolynomial:
    coefficients: list[FiniteFieldElement]
    representation: RingRepresentation

    def __init__(self, coefficients: list[FiniteFieldElement] | None = None, representation: RingRepresentation = RingRepresentation.STANDARD):
        if coefficients is None:
            coefficients = [FiniteFieldElement(0, FIELD_MODULUS) for _ in range(POLYNOMIAL_DEGREE)]
        if len(coefficients) != POLYNOMIAL_DEGREE:
            raise ValueError(f"coefficients must have length {POLYNOMIAL_DEGREE}")
        self.coefficients = coefficients
        self.representation = representation

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KyberPolynomial):
            return NotImplemented
        if self.representation != other.representation:
            return False
        return all([coeff_self == coeff_other for (coeff_self, coeff_other) in zip(self.coefficients, other.coefficients)])

    def __repr__(self) -> str:
        return f"KyberPolynomial({self.coefficients}, {self.representation})"

    def __getitem__(self, coeff_index: int) -> FiniteFieldElement:
        if not (0 <= coeff_index < POLYNOMIAL_DEGREE):
            raise IndexError(f"Index {coeff_index} out of bounds for polynomial with {POLYNOMIAL_DEGREE} coefficients.")
        return self.coefficients[coeff_index]

    def __setitem__(self, coeff_index: int, value: FiniteFieldElement) -> None:
        if not (0 <= coeff_index < POLYNOMIAL_DEGREE):
            raise IndexError(f"Index {coeff_index} out of bounds for polynomial with {POLYNOMIAL_DEGREE} coefficients.")
        self.coefficients[coeff_index] = value

    def __add__(self, other_polynomial: KyberPolynomial) -> KyberPolynomial:
        if self.representation != other_polynomial.representation:
            raise ValueError(f"Cannot add polynomials with different representations: {self.representation} and {other_polynomial.representation}.")
        return KyberPolynomial([coeff_self + coeff_other for (coeff_self, coeff_other) in zip(self.coefficients, other_polynomial.coefficients)], self.representation)

    def __sub__(self, other_polynomial: KyberPolynomial) -> KyberPolynomial:
        if self.representation != other_polynomial.representation:
            raise ValueError(f"Cannot subtract polynomials with different representations: {self.representation} and {other_polynomial.representation}.")
        return KyberPolynomial([coeff_self - coeff_other for (coeff_self, coeff_other) in zip(self.coefficients, other_polynomial.coefficients)], self.representation)

    def __mul__(self, scalar_or_polynomial: FiniteFieldElement | KyberPolynomial) -> KyberPolynomial:
        if isinstance(scalar_or_polynomial, FiniteFieldElement):
            return KyberPolynomial([coeff * scalar_or_polynomial for coeff in self.coefficients], self.representation)
        elif isinstance(scalar_or_polynomial, KyberPolynomial):
            if self.representation != scalar_or_polynomial.representation:
                raise ValueError(f"Cannot multiply polynomials with different representations: {self.representation} and {scalar_or_polynomial.representation}.")
            if self.representation == RingRepresentation.NTT:
                from .mlkem_auxiliary import NumberTheoreticTransform
                return NumberTheoreticTransform.multiply_in_ntt_domain(self, scalar_or_polynomial)
            else:
                product_polynomial = KyberPolynomial(representation=self.representation)
                for first_idx in range(POLYNOMIAL_DEGREE):
                    for second_idx in range(POLYNOMIAL_DEGREE):
                        if first_idx + second_idx < POLYNOMIAL_DEGREE:
                            product_polynomial.coefficients[first_idx + second_idx] = product_polynomial.coefficients[first_idx + second_idx] + (self.coefficients[first_idx] * scalar_or_polynomial.coefficients[second_idx])
                        else:
                            product_polynomial.coefficients[first_idx + second_idx - POLYNOMIAL_DEGREE] = product_polynomial.coefficients[first_idx + second_idx - POLYNOMIAL_DEGREE] - (self.coefficients[first_idx] * scalar_or_polynomial.coefficients[second_idx])
                return product_polynomial
        else:
            raise TypeError(f"Cannot multiply KyberPolynomial by {type(scalar_or_polynomial)}")

    def __rmul__(self, scalar_or_polynomial: FiniteFieldElement | KyberPolynomial) -> KyberPolynomial:
        return self.__mul__(scalar_or_polynomial)