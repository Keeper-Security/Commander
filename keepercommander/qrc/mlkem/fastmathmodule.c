#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdint.h>
#include <stdlib.h>

#define N 256
#define Q 3329

#define ROUND(x, y) (((2 * (x)) + (y)) / (2 * (y)))

const uint16_t ZETA[128] = {
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
};

const uint16_t GAMMA[128] = {
    17, 3312, 2761, 568, 583, 2746, 2649, 680,
    1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662, 667, 3281, 48, 233, 3096,
    756, 2573, 2156, 1173, 3015, 314, 3050, 279,
    1703, 1626, 1651, 1678, 2789, 540, 1789, 1540,
    1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
    939, 2390, 2308, 1021, 2437, 892, 2388, 941,
    733, 2596, 2337, 992, 268, 3061, 641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
    375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
    1063, 2266, 319, 3010, 2773, 556, 757, 2572,
    2099, 1230, 561, 2768, 2466, 863, 2594, 735,
    2804, 525, 1092, 2237, 403, 2926, 1026, 2303,
    1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
    2110, 1219, 2935, 394, 885, 2444, 2154, 1175
};

typedef struct polynomial {
    uint16_t coeffs[N];
} polynomial_t;

typedef struct pair {
    uint16_t first;
    uint16_t second;
} pair_t;

/***** FIELD MATH *****/
uint16_t addMod(const uint16_t x, const uint16_t y) {
    return (x + y) % Q;
}

uint16_t subMod(const uint16_t x, const uint16_t y) {
    return (x + Q - y) % Q;
}

uint16_t mulMod(const uint16_t x, const uint16_t y) {
    uint32_t intermediate = x*y;
    return intermediate % Q;
}

/***** POLYNOMIAL MATH *****/
polynomial_t addPoly(const polynomial_t x, const polynomial_t y) {
    polynomial_t result = { .coeffs = {0} };

    for (unsigned i = 0; i < N; i++) {
        result.coeffs[i] = addMod(x.coeffs[i], y.coeffs[i]);
    }

    return result;
}

polynomial_t subPoly(const polynomial_t x, const polynomial_t y) {
    polynomial_t result = { .coeffs = {0} };

    for (unsigned i = 0; i < N; i++) {
        result.coeffs[i] = subMod(x.coeffs[i], y.coeffs[i]);
    }

    return result;
}

polynomial_t mulScalarPoly(const polynomial_t x, const uint16_t y) {
    polynomial_t result = { .coeffs = {0} };

    for (unsigned i = 0; i < N; i++) {
        result.coeffs[i] = mulMod(x.coeffs[i], y);
    }

    return result;
}

polynomial_t samplePolyCBD(const unsigned char * bytes, unsigned eta) {
    polynomial_t result = { .coeffs = {0} };

    for (unsigned i = 0; i < N; i++) {
        uint16_t x = 0, y = 0;

        for (unsigned j = 0; j < eta; j++) {
            div_t xqr = div(2*i*eta + j, 8);
            x += (bytes[xqr.quot] >> xqr.rem) & 1;

            div_t yqr = div(2*i*eta + eta + j, 8);
            y += (bytes[yqr.quot] >> yqr.rem) & 1;
        }

        result.coeffs[i] = subMod(x, y);
    }

    return result;
}

void byteEncodePoly(const unsigned d, const polynomial_t f, unsigned char * const bytes) {
    for (unsigned i = 0; i < N; i++) {
        uint16_t a = f.coeffs[i];

        for (unsigned j = 0; j < d; j++) {
            div_t qr = div(i*d + j, 8);
            bytes[qr.quot] |= ((a & 1) << (qr.rem));
            a /= 2;
        }
    }
}

polynomial_t byteDecodePoly(const unsigned d, const unsigned char * const bytes) {
    polynomial_t result = { .coeffs = {0} };
    for (unsigned i = 0; i < N; i++) {
        for (unsigned j = 0; j < d; j++) {
            div_t qr = div(i*d + j, 8);
            result.coeffs[i] |= ((bytes[qr.quot] >> qr.rem) & 1) << j;
        }
    }
    return result;
}

polynomial_t compressPoly(const unsigned d, const polynomial_t f) {
    polynomial_t result = { .coeffs = {0} };
    for (unsigned i = 0; i < N; i++) {
        uint16_t x = f.coeffs[i];
        uint16_t y = ROUND(((1 << d) * x), Q);
        result.coeffs[i] = y % (1 << d);
    }
    return result;
}

polynomial_t decompressPoly(const unsigned d, const polynomial_t f) {
    polynomial_t result = { .coeffs = {0} };
    for (unsigned i = 0; i < N; i++) {
        uint16_t y = f.coeffs[i];
        uint16_t x = ROUND((Q * y), (1 << d));
        result.coeffs[i] = x;
    }
    return result;
}

/***** NTT MATH *****/
polynomial_t ntt(const polynomial_t x) {
    polynomial_t result = { .coeffs = {0} };
    for (unsigned i = 0; i < N; i++) {
        result.coeffs[i] = x.coeffs[i];
    }
    unsigned i = 1;

    for (unsigned len = 128; len >= 2; len = len/2) {
        for (unsigned start = 0; start < 256; start = start + 2*len) {
            uint16_t zeta = ZETA[i];
            i++;

            for (unsigned j = start; j < start + len; j++) {
                uint16_t t = mulMod(zeta, result.coeffs[j + len]);
                result.coeffs[j + len] = subMod(result.coeffs[j], t);
                result.coeffs[j] = addMod(result.coeffs[j], t);
            }
        }
    }

    return result;
}

polynomial_t nttInv(const polynomial_t x) {
    polynomial_t result = { .coeffs = {0} };
    for (unsigned i = 0; i < N; i++) {
        result.coeffs[i] = x.coeffs[i];
    }
    unsigned i = 127;

    for (unsigned len = 2; len <= 128; len = len*2) {
        for (unsigned start = 0; start < N; start = start + 2*len) {
            uint16_t zeta = ZETA[i];
            i--;

            for (unsigned j = start; j < start + len; j++) {
                uint16_t t = result.coeffs[j];
                result.coeffs[j] = addMod(t, result.coeffs[j + len]);
                result.coeffs[j + len] = mulMod(zeta, subMod(result.coeffs[j + len], t));
            }
        }
    }

    return mulScalarPoly(result, 3303);
}

pair_t multiplyNttBaseCase(const uint16_t a0, const uint16_t a1, const uint16_t b0, const uint16_t b1, const uint16_t gamma) {
    uint16_t c0 = addMod(mulMod(a0, b0), mulMod(mulMod(a1, b1), gamma));
    uint16_t c1 = addMod(mulMod(a0, b1), mulMod(a1, b0));
    pair_t result = { .first = c0, .second = c1 };
    return result;
}

polynomial_t multiplyNtt(const polynomial_t x, const polynomial_t y) {
    polynomial_t result = { .coeffs = {0} };

    for (unsigned i = 0; i < 128; i++) {
        unsigned j = 2 * i, k = 2 * i + 1;
        uint16_t gamma = GAMMA[i];
        pair_t c = multiplyNttBaseCase(x.coeffs[j], x.coeffs[k], y.coeffs[j], y.coeffs[k], gamma);
        result.coeffs[j] = c.first;
        result.coeffs[k] = c.second;
    }

    return result;
}

polynomial_t sampleNtt(const unsigned char * const bytes) {
    polynomial_t a = { .coeffs = {0} };
    unsigned j = 0;
    unsigned i = 0;

    while (j < N) {
        const uint16_t c0 = bytes[i], c1 = bytes[i+1], c2 = bytes[i+2];
        // uint16_t d1 = c0 + ((c1 & 0xf) << 8);
        // uint16_t d2 = (c1 >> 4) + (c2 << 4);
        uint16_t d1 = c0 + 256 * (c1 % 16);
        uint16_t d2 = c1 / 16 + 16 * c2;

        if (d1 < Q) {
            a.coeffs[j] = d1;
            j++;
        }
        if (d2 < Q && j < N) {
            a.coeffs[j] = d2;
            j++;
        }

        i += 3;
    }

    return a;
}

/***** MATRIX MATH *****/
// get the index in a flat array using row-major order
size_t idx(size_t row, size_t col, size_t totalCols) {
    return row * totalCols + col;
}

void addMatrix(const polynomial_t * const x, const polynomial_t * const y, polynomial_t * const z, size_t k) {
    for (size_t i = 0; i < k; i++) {
        z[i] = addPoly(x[i], y[i]);
    }
}

// TODO - can be optimized via e.g. Strassen's algorithm.
void mulMatrix(const polynomial_t * const x, const polynomial_t * const y, polynomial_t * z, const unsigned xrow, const unsigned xcol, const unsigned yrow, const unsigned ycol) {
    for (unsigned i = 0; i < xrow; i++) {
        for (unsigned j = 0; j < ycol; j++) {
            polynomial_t entry = { .coeffs = {0} };

            for (unsigned k = 0; k < xcol; k++) {
                polynomial_t product = multiplyNtt(x[idx(i, k, xcol)], y[idx(k, j, ycol)]);
                entry = addPoly(entry, product);
            }

            z[idx(i, j, ycol)] = entry;
        }
    }
}

void mapNttMatrix(const polynomial_t * const x, polynomial_t * const y, const size_t k) {
    for (size_t i = 0; i < k; i++) {
        y[i] = ntt(x[i]);
    }
}

void mapNttInvMatrix(const polynomial_t * const x, polynomial_t * const y, const size_t k) {
    for (size_t i = 0; i < k; i++) {
        y[i] = nttInv(x[i]);
    }
}

void byteEncodeMatrix(const unsigned d, const polynomial_t * const f, unsigned char * const bytes, const size_t k) {
    for (size_t i = 0; i < k; i ++) {
        byteEncodePoly(d, f[i], &bytes[i*32*d]);
    }
}

polynomial_t * byteDecodeMatrix(const unsigned d, const unsigned char * const bytes, const size_t k) {
    polynomial_t * result = malloc(k * sizeof(polynomial_t));
    for (unsigned i = 0; i < k; i++) {
        result[i] = byteDecodePoly(d, &bytes[i*32*d]);
    }
    return result;
}

void compressMatrix(const unsigned d, const polynomial_t * const x, polynomial_t * const y, const size_t k) {
    for (size_t i = 0; i < k; i++) {
        y[i] = compressPoly(d, x[i]);
    }
}

void decompressMatrix(const unsigned d, const polynomial_t * const x, polynomial_t * const y, const size_t k) {
    for (size_t i = 0; i < k; i++) {
        y[i] = decompressPoly(d, x[i]);
    }
}

/***** PYTHON BINDINGS *****/
// parse polynomial (array of N ints) passed from python-land
polynomial_t parsePolynomial(PyObject * const data) {
    polynomial_t result = { .coeffs = {0} };
    for (Py_ssize_t i = 0; i < N; i++) {
        PyObject * item = PyList_GetItem(data, i);
        result.coeffs[i] = (uint16_t)PyLong_AsLong(item);
    }
    return result;
}

// parser a matrix (array of N int arrays) passed from python-land
// the matrix MUST be freed by the caller to avoid a memory leak
polynomial_t * parseMatrix(PyObject * const data, const Py_ssize_t entries) {
    polynomial_t * matrix = malloc(entries * sizeof(polynomial_t));
    for (Py_ssize_t i = 0; i < entries; i++) {
        PyObject * entry = PyList_GetItem(data, i);
        matrix[i] = parsePolynomial(entry);
    }
    return matrix;
}

// package a polynomial_t to be passed to python-land as an integer list
PyObject * composePolynomial(const polynomial_t data) {
    PyObject * output = PyList_New(N);
    for (Py_ssize_t i = 0; i < N; i++) {
        PyObject * value = PyLong_FromLong(data.coeffs[i]);
        PyList_SetItem(output, i, value);
    }
    return output;
}

// package a matrix (array of polynomial_t) to be passed to python-land as a list of integer lists
PyObject * composeMatrix(const polynomial_t * const data, const Py_ssize_t entries) {
    PyObject * output = PyList_New(entries);
    for (Py_ssize_t i = 0; i < entries; i++) {
        PyList_SetItem(output, i, composePolynomial(data[i]));
    }
    return output;
}

// addPoly
static PyObject * fastmath_add_poly(PyObject * self, PyObject * args) {
    // parse input
    PyObject * intList1, * intList2;
    if (!PyArg_ParseTuple(args, "O!O!", &PyList_Type, &intList1, &PyList_Type, &intList2)) {
        return NULL;
    }
    polynomial_t x = parsePolynomial(intList1);
    polynomial_t y = parsePolynomial(intList2);
    // perform the call
    polynomial_t z = addPoly(x, y);
    // package the output
    return composePolynomial(z);
}

// subPoly
static PyObject * fastmath_sub_poly(PyObject * self, PyObject * args) {
    // parse input
    PyObject * intList1, * intList2;
    if (!PyArg_ParseTuple(args, "O!O!", &PyList_Type, &intList1, &PyList_Type, &intList2)) {
        return NULL;
    }
    polynomial_t x = parsePolynomial(intList1);
    polynomial_t y = parsePolynomial(intList2);
    // perform the call
    polynomial_t z = subPoly(x, y);
    // package the output
    return composePolynomial(z);
}

// samplePolyCBD binding
static PyObject * fastmath_sample_poly_cbd(PyObject * self, PyObject * args) {
    // parse input
    PyObject * bytes;
    unsigned eta;
    if (!PyArg_ParseTuple(args, "SI", &bytes, &eta)) {
        return NULL;
    }
    // perform the call
    polynomial_t result = samplePolyCBD((unsigned char *)PyBytes_AsString(bytes), eta);
    // package output
    return composePolynomial(result);
}

// byteEncodePoly
static PyObject * fastmath_byte_encode_poly(PyObject * self, PyObject * args) {
    // parse input
    PyObject * intList;
    unsigned d;
    if (!PyArg_ParseTuple(args, "O!I", &PyList_Type, &intList, &d)) {
        return NULL;
    }
    polynomial_t input = parsePolynomial(intList);
    const size_t numBytes = 32 * d;
    unsigned char * bytes = calloc(numBytes, sizeof(unsigned char));

    // perform the call
    byteEncodePoly(d, input, bytes);

    // package output
    PyObject * result = PyBytes_FromStringAndSize((char *)bytes, numBytes * sizeof(unsigned char));
    free(bytes);
    return result;
}

// byteDecodePoly
static PyObject * fastmath_byte_decode_poly(PyObject * self, PyObject * args) {
    // parse input
    PyObject * bytes;
    unsigned d;
    if (!PyArg_ParseTuple(args, "SI", &bytes, &d)) {
        return NULL;
    }
    // perform the call
    polynomial_t result = byteDecodePoly(d, (unsigned char *)PyBytes_AsString(bytes));
    // package output
    return composePolynomial(result);
}

// compressPoly
static PyObject * fastmath_compress_poly(PyObject * self, PyObject * args) {
    // parse input
    PyObject * intList;
    unsigned d;
    if (!PyArg_ParseTuple(args, "O!I", &PyList_Type, &intList, &d)) {
        return NULL;
    }
    polynomial_t input = parsePolynomial(intList);
    // perform the call
    polynomial_t result = compressPoly(d, input);
    // package output
    return composePolynomial(result);
}

// decompressPoly
static PyObject * fastmath_decompress_poly(PyObject * self, PyObject * args) {
    // parse input
    PyObject * intList;
    unsigned d;
    if (!PyArg_ParseTuple(args, "O!I", &PyList_Type, &intList, &d)) {
        return NULL;
    }
    polynomial_t input = parsePolynomial(intList);
    // perform the call
    polynomial_t result = decompressPoly(d, input);
    // package output
    return composePolynomial(result);
}

// nttInv binding
static PyObject * fastmath_ntt_inv(PyObject * self, PyObject * args) {
    // parse input
    PyObject * intList;
    if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &intList)) {
        return NULL;
    }
    polynomial_t input = parsePolynomial(intList);
    // perform the call
    polynomial_t result = nttInv(input);
    // package output
    return composePolynomial(result);
}

// sampleNtt binding
static PyObject * fastmath_sample_ntt(PyObject * self, PyObject * args) {
    // parse input
    PyObject * bytes;
    if (!PyArg_ParseTuple(args, "S", &bytes)) {
        return NULL;
    }
    // perform the call
    polynomial_t result = sampleNtt((unsigned char *)PyBytes_AsString(bytes));
    // package output
    return composePolynomial(result);
}

// addMatrix
static PyObject * fastmath_add_matrix(PyObject * self, PyObject * args) {
    // parse input
    PyObject * matrix1, * matrix2;
    if (!PyArg_ParseTuple(args, "O!O!", &PyList_Type, &matrix1, &PyList_Type, &matrix2)) {
        return NULL;
    }
    const Py_ssize_t entries = PyList_Size(matrix1);
    polynomial_t * x = parseMatrix(matrix1, entries);
    polynomial_t * y = parseMatrix(matrix2, entries);

    // perform the call
    polynomial_t * z = malloc(entries * sizeof(polynomial_t));
    addMatrix(x, y, z, entries);

    // package output and cleanup
    PyObject * result = composeMatrix(z, entries);
    free(z);
    free(y);
    free(x);
    return result;
}

// mulScalarMatrix
static PyObject * fastmath_mul_matrix(PyObject * self, PyObject * args) {
    // parse input
    PyObject * matrix1, * matrix2;
    unsigned xrow, xcol, yrow, ycol;
    if (!PyArg_ParseTuple(args, "O!O!IIII", &PyList_Type, &matrix1, &PyList_Type, &matrix2, &xrow, &xcol, &yrow, &ycol)) {
        return NULL;
    }
    polynomial_t * x = parseMatrix(matrix1, PyList_Size(matrix1));
    polynomial_t * y = parseMatrix(matrix2, PyList_Size(matrix2));
    unsigned entries = xrow * ycol;

    // perform the call
    polynomial_t * z = malloc(entries * sizeof(polynomial_t));
    mulMatrix(x, y, z, xrow, xcol, yrow, ycol);

    // package output and cleanup
    PyObject * result = composeMatrix(z, entries);
    free(z);
    free(y);
    free(x);
    return result;
}

// mapNttMatrix
static PyObject * fastmath_map_ntt_matrix(PyObject * self, PyObject * args) {
    // parse input
    PyObject * matrix;
    if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &matrix)) {
        return NULL;
    }
    const Py_ssize_t entries = PyList_Size(matrix);
    polynomial_t * x = parseMatrix(matrix, entries);

    // perform the call
    polynomial_t * y = malloc(entries * sizeof(polynomial_t));
    mapNttMatrix(x, y, entries);

    // package output and cleanup
    PyObject * result = composeMatrix(y, entries);
    free(y);
    free(x);
    return result;
}

// mapNttInvMatrix
static PyObject * fastmath_map_ntt_inv_matrix(PyObject * self, PyObject * args) {
    // parse input
    PyObject * matrix;
    if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &matrix)) {
        return NULL;
    }
    const Py_ssize_t entries = PyList_Size(matrix);
    polynomial_t * x = parseMatrix(matrix, entries);

    // perform the call
    polynomial_t * y = malloc(entries * sizeof(polynomial_t));
    mapNttInvMatrix(x, y, entries);

    // package output and cleanup
    PyObject * result = composeMatrix(y, entries);
    free(y);
    free(x);
    return result;
}

// byteEncodeMatrix
static PyObject * fastmath_byte_encode_matrix(PyObject * self, PyObject * args) {
    // // parse input
    PyObject * matrix;
    unsigned d;
    if (!PyArg_ParseTuple(args, "O!I", &PyList_Type, &matrix, &d)) {
        return NULL;
    }
    const Py_ssize_t entries = PyList_Size(matrix);
    polynomial_t * x = parseMatrix(matrix, entries);

    // perform the call
    // each entry has 256 elements. If we have d bits per entry and 8 bits per byte we need (256 * d) / 8 bytes per entry = 32 * d
    const size_t numBytes = 32 * d * entries;
    unsigned char * bytes = calloc(numBytes, sizeof(unsigned char));
    byteEncodeMatrix(d, x, bytes, entries);

    // package output and cleanup
    PyObject * result = PyBytes_FromStringAndSize((char *)bytes, numBytes * sizeof(unsigned char));
    free(bytes);
    free(x);
    return result;
}

// byteDecodeMatrix
static PyObject * fastmath_byte_decode_matrix(PyObject * self, PyObject * args) {
    // // parse input
    PyObject * bytes;
    unsigned d, entries;
    if (!PyArg_ParseTuple(args, "SII", &bytes, &d, &entries)) {
        return NULL;
    }

    // perform the call
    polynomial_t * x = byteDecodeMatrix(d, (unsigned char *)PyBytes_AsString(bytes), entries);

    // package output and cleanup
    PyObject * result = composeMatrix(x, entries);
    free(x);
    return result;
}

// compressMatrix
static PyObject * fastmath_compress_matrix(PyObject * self, PyObject * args) {
    // parse input
    PyObject * matrix;
    unsigned d;
    if (!PyArg_ParseTuple(args, "O!I", &PyList_Type, &matrix, &d)) {
        return NULL;
    }
    const Py_ssize_t entries = PyList_Size(matrix);
    polynomial_t * x = parseMatrix(matrix, entries);

    // perform the call
    polynomial_t * y = malloc(entries * sizeof(polynomial_t));
    compressMatrix(d, x, y, entries);

    // package output and cleanup
    PyObject * result = composeMatrix(y, entries);
    free(y);
    free(x);
    return result;
}

// decompressMatrix
static PyObject * fastmath_decompress_matrix(PyObject * self, PyObject * args) {
    // parse input
    PyObject * matrix;
    unsigned d;
    if (!PyArg_ParseTuple(args, "O!I", &PyList_Type, &matrix, &d)) {
        return NULL;
    }
    const Py_ssize_t entries = PyList_Size(matrix);
    polynomial_t * x = parseMatrix(matrix, entries);

    // perform the call
    polynomial_t * y = malloc(entries * sizeof(polynomial_t));
    decompressMatrix(d, x, y, entries);

    // package output and cleanup
    PyObject * result = composeMatrix(y, entries);
    free(y);
    free(x);
    return result;
}

// methods available to python-land
static PyMethodDef FastMathMethods[] = {
    {"add_poly", fastmath_add_poly, METH_VARARGS, "Add two polynomials."},
    {"sub_poly", fastmath_sub_poly, METH_VARARGS, "Subtract two polynomials."},
    {"sample_poly_cbd", fastmath_sample_poly_cbd, METH_VARARGS, "Sample an element from a centered binomial distribution."},
    {"byte_encode_poly", fastmath_byte_encode_poly, METH_VARARGS, "Serializea polynomial to bytes."},
    {"byte_decode_poly", fastmath_byte_decode_poly, METH_VARARGS, "Deserialize bytes to a polynomial."},
    {"compress_poly", fastmath_compress_poly, METH_VARARGS, "Map the elements of a polynomial from Z_q to Z_{2^d}."},
    {"decompress_poly", fastmath_decompress_poly, METH_VARARGS, "Map the elements of a polynomial from Z_{2^d} to Z_q."},
    {"ntt_inv", fastmath_ntt_inv, METH_VARARGS, "Perform the inverse Number Theoretic Transform (NTT)."},
    {"sample_ntt", fastmath_sample_ntt, METH_VARARGS, "Sample an element in NTT representation."},
    {"add_matrix", fastmath_add_matrix, METH_VARARGS, "Add two matrices."},
    {"mul_matrix", fastmath_mul_matrix, METH_VARARGS, "Multiply two matrices."},
    {"map_ntt_matrix", fastmath_map_ntt_matrix, METH_VARARGS, "Map the NTT onto all elements in a matrix."},
    {"map_ntt_inv_matrix", fastmath_map_ntt_inv_matrix, METH_VARARGS, "Map the inverse NTT onto all elements in a matrix."},
    {"byte_encode_matrix", fastmath_byte_encode_matrix, METH_VARARGS, "Serialize a matrix to bytes."},
    {"byte_decode_matrix", fastmath_byte_decode_matrix, METH_VARARGS, "Deserialize a bytes to a matrix."},
    {"compress_matrix", fastmath_compress_matrix, METH_VARARGS, "Map the elements of each polynomial in a matrix from Z_q to Z_{2^d}."},
    {"decompress_matrix", fastmath_decompress_matrix, METH_VARARGS, "Map the elements of each polynomial in a matrix from Z_{2^d} to Z_q."},
    {NULL, NULL, 0, NULL}
};

// definition of the fastmath module
static struct PyModuleDef fastmathmodule = {
    PyModuleDef_HEAD_INIT,
    "fastmath",
    NULL,
    -1,
    FastMathMethods
};

PyMODINIT_FUNC PyInit_fastmath(void) {
    return PyModule_Create(&fastmathmodule);
}
