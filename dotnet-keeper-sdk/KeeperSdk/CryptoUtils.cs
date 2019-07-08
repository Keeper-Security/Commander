//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Paddings;

namespace KeeperSecurity.Sdk
{
    public static class CryptoUtils
    {
        const string CorruptedEncryptionParametersMessage = "Corrupted encryption parameters";

        static readonly RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        public static byte[] GetRandomBytes(int length)
        {
            var bytes = new byte[length];
            rngCsp.GetBytes(bytes);
            return bytes;
        }

        public static byte[] GenerateEncryptionKey()
        {
            return GetRandomBytes(32);
        }

        public static string GenerateUid()
        {
            return GetRandomBytes(16).Base64UrlEncode();
        }

        public static string Base64UrlEncode(this byte[] data)
        {
            var base64 = Convert.ToBase64String(data);
            return base64.TrimEnd('=').Replace("+", "-").Replace("/", "_");
        }

        public static byte[] Base64UrlDecode(this string text)
        {
            if (text == null) return null;
            var base64 = text.Replace("-", "+").Replace("_", "/");
            base64 = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
            try
            {
                return Convert.FromBase64String(base64);
            }
            catch
            {
                return new byte[] { };
            }
        }

        public static RsaKeyParameters LoadPublicKey(this byte[] key)
        {

            var algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            var publicKeyStructure = RsaPublicKeyStructure.GetInstance(Asn1Sequence.GetInstance(key));
            var publicKeyInfo = new SubjectPublicKeyInfo(algorithm, publicKeyStructure);

            return PublicKeyFactory.CreateKey(publicKeyInfo) as RsaKeyParameters;
        }

        public static RsaPrivateCrtKeyParameters LoadPrivateKey(this byte[] key)
        {
            var algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            var prvateKeyStructure = RsaPrivateKeyStructure.GetInstance(Asn1Sequence.GetInstance(key));
            var privateKeyInfo = new PrivateKeyInfo(algorithm, prvateKeyStructure);

            return PrivateKeyFactory.CreateKey(privateKeyInfo) as RsaPrivateCrtKeyParameters;
        }

        public static byte[] EncryptAesV1(byte[] data, byte[] key, byte[] iv = null)
        {
            iv = iv ?? GetRandomBytes(16);
            var parameters = new ParametersWithIV(new KeyParameter(key), iv);

            var aes = new AesEngine();
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
            cipher.Init(true, parameters);

            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);

            return iv.Concat(cipherText.Take(len)).ToArray();
        }

        public static byte[] DecryptAesV1(byte[] data, byte[] key)
        {
            var iv = data.Take(16).ToArray();
            var parameters = new ParametersWithIV(new KeyParameter(key), iv);

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
            cipher.Init(false, parameters);

            var decryptedData = new byte[cipher.GetOutputSize(data.Length - 16)];
            var len = cipher.ProcessBytes(data, 16, data.Length - 16, decryptedData, 0);
            len += cipher.DoFinal(decryptedData, len);

            return decryptedData.Take(len).ToArray();
        }


        const int AesGcmNonceLength = 12;
        public static byte[] EncryptAesV2(byte[] data, byte[] key, byte[] nonce = null)
        {
            nonce = nonce ?? GetRandomBytes(AesGcmNonceLength);
            var parameters = new AeadParameters(new KeyParameter(key), 16 * 8, nonce);

            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(true, parameters);

            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);

            return nonce.Concat(cipherText.Take(len)).ToArray();
        }

        public static byte[] DecryptAesV2(byte[] data, byte[] key)
        {
            var nonce = data.Take(AesGcmNonceLength).ToArray();
            var parameters = new AeadParameters(new KeyParameter(key), 16 * 8, nonce);

            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, parameters);
            var decryptedData = new byte[cipher.GetOutputSize(data.Length - AesGcmNonceLength)];

            var len = cipher.ProcessBytes(data, AesGcmNonceLength, data.Length - AesGcmNonceLength, decryptedData, 0);
            len += cipher.DoFinal(decryptedData, len);

            return decryptedData.Take(len).ToArray();
        }

        public static byte[] EncryptRsa(byte[] data, RsaKeyParameters publicKey)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, publicKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        public static byte[] DecryptRsa(byte[] data, RsaPrivateCrtKeyParameters privateKey)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(false, privateKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        public static byte[] DeriveKeyV1(string password, byte[] salt, int iterations)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pdb.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray()), salt, iterations);
            return ((KeyParameter)pdb.GenerateDerivedMacParameters(32 * 8)).GetKey();
        }

        public static byte[] DeriveV1KeyHash(string password, byte[] salt, int iterations)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pdb.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray()), salt, iterations);
            var key = ((KeyParameter)pdb.GenerateDerivedMacParameters(32 * 8)).GetKey();

            return SHA256.Create().ComputeHash(key);
        }

        public static byte[] CreateAuthVerifier(string password, byte[] salt, int iterations)
        {
            var versionBytes = BitConverter.GetBytes(1);
            var iterationsBytes = BitConverter.GetBytes(iterations);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(iterationsBytes);
            }
            var key = DeriveKeyV1(password, salt, iterations);
            return new[] { versionBytes.Take(1), iterationsBytes.Skip(1), salt, key }.SelectMany(x => x).ToArray();
        }

        public static byte[] CreateEncryptionParams(string password, byte[] salt, int iterations, byte[] dataKey)
        {
            var versionBytes = BitConverter.GetBytes(1);
            var iterationsBytes = BitConverter.GetBytes(iterations);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(iterationsBytes);
            }
            var key = DeriveKeyV1(password, salt, iterations);
            var iv = GetRandomBytes(16);
            var parameters = new ParametersWithIV(new KeyParameter(key), iv);

            var cipher = new CbcBlockCipher(new AesEngine());
            cipher.Init(true, parameters);
            var outBuffer = new byte[dataKey.Length * 2];
            int len = 0;
            int blockSize = cipher.GetBlockSize();
            while (len < outBuffer.Length)
            {
                int offset = len % dataKey.Length;
                len += cipher.ProcessBlock(dataKey, offset, outBuffer, len);
            }

            return new[] { versionBytes.Take(1), iterationsBytes.Skip(1), salt, iv, outBuffer }.SelectMany(x => x).ToArray();
        }

        public static byte[] DecryptEncryptionParams(string password, byte[] encryptionParams)
        {
            if (encryptionParams[0] != 1)
            {
                throw new Exception(CorruptedEncryptionParametersMessage);
            }
            if (encryptionParams.Length != 1 + 3 + 16 + 16 + 64)
            {
                throw new Exception(CorruptedEncryptionParametersMessage);
            }
            int iterations = (encryptionParams[1] << 16) + (encryptionParams[2] << 8) + encryptionParams[3];

            var salt = new byte[16];
            Array.Copy(encryptionParams, 4, salt, 0, 16);
            var key = DeriveKeyV1(password, salt, iterations);

            Array.Copy(encryptionParams, 20, salt, 0, 16);
            var parameters = new ParametersWithIV(new KeyParameter(key), salt);

            var aes = new AesEngine();
            var cipher = new CbcBlockCipher(new AesEngine());
            cipher.Init(false, parameters);
            int len = 0;
            int blockSize = cipher.GetBlockSize();
            var outBuffer = new byte[64];
            while (len < 64)
            {
                len += cipher.ProcessBlock(encryptionParams, len + 36, outBuffer, len);
            }
            if (!outBuffer.Take(32).SequenceEqual(outBuffer.Skip(32)))
            {
                throw new Exception(CorruptedEncryptionParametersMessage);
            }
            return outBuffer.Take(32).Take(32).ToArray();
        }

        public static byte[] DeriveKeyV2(string domain, string password, byte[] salt, int iterations)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(domain + password);

            var pdb = new Pkcs5S2ParametersGenerator(new Sha512Digest());
            pdb.Init(passwordBytes, salt, iterations);
            var key = ((KeyParameter)pdb.GenerateDerivedMacParameters(64 * 8)).GetKey();

            var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(domain));
        }
    }

    public class EncryptTransform : ICryptoTransform
    {
        public int InputBlockSize => cypher.GetBlockSize();

        public int OutputBlockSize => cypher.GetBlockSize();

        public bool CanTransformMultipleBlocks => true;

        public bool CanReuseTransform => false;

        readonly IBufferedCipher cypher;
        byte[] tail;

        public long EncryptedBytes { get; private set; }

        public EncryptTransform(IBufferedCipher cypher, byte[] key)
        {
            this.cypher = cypher;
            var iv = CryptoUtils.GetRandomBytes(cypher.GetBlockSize());
            this.cypher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            tail = iv;
            EncryptedBytes = 0;
        }

        public void Dispose()
        {
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset)
        {
            EncryptedBytes += inputCount;
            var encrypted = cypher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            if (tail.Length > 0)
            {
                if (tail.Length <= outputBuffer.Length + outputOffset + encrypted)
                {
                    Array.Copy(outputBuffer, outputOffset, outputBuffer, outputOffset + tail.Length, encrypted);
                    Array.Copy(tail, 0, outputBuffer, outputOffset, tail.Length);
                    encrypted += tail.Length;
                    tail = new byte[0];
                }
                else
                {
                    if (tail.Length <= encrypted)
                    {
                        var newTail = new byte[tail.Length];
                        Array.Copy(outputBuffer, outputOffset + encrypted - tail.Length, newTail, 0, tail.Length);
                        Array.Copy(outputBuffer, outputOffset, outputBuffer, outputOffset + tail.Length, encrypted);
                        Array.Copy(tail, 0, outputBuffer, outputOffset, tail.Length);
                        tail = newTail;
                    }
                    else
                    {
                        var newTail = new byte[tail.Length + encrypted];
                        Array.Copy(tail, 0, newTail, 0, tail.Length);
                        Array.Copy(outputBuffer, outputOffset, newTail, tail.Length, encrypted);
                        tail = newTail;
                        encrypted = 0;
                    }
                }
            }
            return encrypted;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            EncryptedBytes += inputCount;
            var final = cypher.DoFinal(inputBuffer, inputOffset, inputCount);
            var result = new byte[tail.Length + final.Length];
            Array.Copy(tail, 0, result, 0, tail.Length);
            Array.Copy(final, 0, result, tail.Length, final.Length);
            return result;
        }
    }

    public class DecryptTransform : ICryptoTransform
    {
        public int InputBlockSize => cypher.GetBlockSize();

        public int OutputBlockSize => cypher.GetBlockSize();

        public bool CanTransformMultipleBlocks => true;

        public bool CanReuseTransform => false;

        readonly IBufferedCipher cypher;
        readonly byte[] key;
        bool initialized;

        public long DecryptedBytes { get; private set; }

        public DecryptTransform(IBufferedCipher cypher, byte[] key)
        {
            this.cypher = cypher;
            this.key = key;
            initialized = false;
            DecryptedBytes = 0;
        }

        public void Dispose()
        {
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset)
        {
            if (!initialized)
            {
                var iv = new byte[cypher.GetBlockSize()];
                Array.Copy(inputBuffer, inputOffset, iv, 0, iv.Length);
                inputOffset += iv.Length;
                inputCount -= iv.Length;
                cypher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
                initialized = true;
            }
            var res = cypher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            DecryptedBytes += res;
            return res;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (!initialized)
            {
                var iv = new byte[cypher.GetBlockSize()];
                Array.Copy(inputBuffer, inputOffset, iv, 0, iv.Length);
                inputOffset += iv.Length;
                inputCount -= iv.Length;
                cypher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
                initialized = true;
            }

            var res = cypher.DoFinal(inputBuffer, inputOffset, inputCount);
            DecryptedBytes += res.LongLength;
            return res;
        }
    }

    public class EncryptAesV1Transform : EncryptTransform
    {
        public EncryptAesV1Transform(byte[] key) : base(new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()), key)
        {
        }
    }

    public class DecryptAesV1Transform : DecryptTransform
    {
        public DecryptAesV1Transform(byte[] key) : base(new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()), key)
        {
        }
    }
}
