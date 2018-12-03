using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace DukptNet
{
    public static class Dukpt
    {

        #region Private Mask Constants

        private static readonly BigInteger Reg3Mask = "1FFFFF".HexToBigInteger();
        private static readonly BigInteger ShiftRegMask = "100000".HexToBigInteger();
        private static readonly BigInteger Reg8Mask = "FFFFFFFFFFE00000".HexToBigInteger();
        private static readonly BigInteger Ls16Mask = "FFFFFFFFFFFFFFFF".HexToBigInteger();
        private static readonly BigInteger Ms16Mask = "FFFFFFFFFFFFFFFF0000000000000000".HexToBigInteger();
        private static readonly BigInteger KeyMask = "C0C0C0C000000000C0C0C0C000000000".HexToBigInteger();
        private static readonly BigInteger PekMask = "FF00000000000000FF".HexToBigInteger();
        private static readonly BigInteger KsnMask = "FFFFFFFFFFFFFFE00000".HexToBigInteger();
        private static readonly BigInteger DekMask = "0000000000FF00000000000000FF0000".HexToBigInteger();
        private static readonly BigInteger MacMask = "000000000000FF00000000000000FF00".HexToBigInteger();

        #endregion

        #region Private Methods

        /// <summary>
        /// Create Initial PIN Encryption Key
        /// </summary>
        /// <param name="ksn">Key Serial Number</param>
        /// <param name="bdk">Base Derivation Key</param>
        /// <returns>Initial PIN Encryption Key</returns>
        private static BigInteger CreateIpek(BigInteger ksn, BigInteger bdk)
        {
            return Transform("TripleDES", true, bdk, (ksn & KsnMask) >> 16) << 64
                 | Transform("TripleDES", true, bdk ^ KeyMask, (ksn & KsnMask) >> 16);
        }

        /// <summary>
        /// Create Session Key with PEK Mask
        /// </summary>
        /// <param name="ipek">Initial PIN Encryption Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <returns>Session Key</returns>
        private static BigInteger CreateSessionKeyPEK(BigInteger ipek, BigInteger ksn)
        {
            return DeriveKey(ipek, ksn) ^ PekMask;
        }

        /// <summary>
        /// Create Session Key with MAC Mask
        /// </summary>
        /// <param name="ipek">Initial PIN Encryption Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <returns>Session Key</returns>
        private static BigInteger CreateSessionKeyMAC(BigInteger ipek, BigInteger ksn)
        {
            return DeriveKey(ipek, ksn) ^ MacMask;
        }

        /// <summary>
        /// Create Session Key with DEK Mask
        /// </summary>
        /// <param name="ipek">Initial PIN Encryption Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <returns>Session Key</returns>
        private static BigInteger CreateSessionKeyDEK(BigInteger ipek, BigInteger ksn) {
			BigInteger key = DeriveKey(ipek, ksn) ^ DekMask;
			return Transform("TripleDES", true, key, (key & Ms16Mask) >> 64) << 64 
				 | Transform("TripleDES", true, key, (key & Ls16Mask));
		}

        /// <summary>
        /// Create Session Key
        /// </summary>
        /// <param name="bdk">Base Derivation Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <param name="dukptVariant">DUKPT variant used to determine session key creation method</param>
        /// <returns>Session Key</returns>
        private static BigInteger CreateSessionKey(string bdk, string ksn, DukptVariant dukptVariant)
        {
            BigInteger ksnBigInt = ksn.HexToBigInteger();
            BigInteger ipek = CreateIpek(ksnBigInt, bdk.HexToBigInteger());
            BigInteger sessionKey;
            switch (dukptVariant)
            {
                case DukptVariant.MAC:
                    sessionKey = CreateSessionKeyMAC(ipek, ksnBigInt);
                    break;
                case DukptVariant.Data:
                    sessionKey = CreateSessionKeyDEK(ipek, ksnBigInt);
                    break;
                case DukptVariant.PIN:
                default:
                    sessionKey = CreateSessionKeyPEK(ipek, ksnBigInt);
                    break;

            }
            return sessionKey;
        }

        /// <summary>
        /// Derive Key from IPEK and KSN
        /// </summary>
        /// <param name="ipek">Initial PIN Encryption Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <returns>Key derived from IPEK and KSN</returns>
        private static BigInteger DeriveKey(BigInteger ipek, BigInteger ksn)
        {
            BigInteger ksnReg = ksn & Ls16Mask & Reg8Mask;
            BigInteger curKey = ipek;
            for (BigInteger shiftReg = ShiftRegMask; shiftReg > 0; shiftReg >>= 1)
            {
                if ((shiftReg & ksn & Reg3Mask) > 0)
                {
                    curKey = GenerateKey(curKey, ksnReg |= shiftReg);
                }
            }
            return curKey;
        }

        /// <summary>
        /// Generate Key
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <returns>Key generated from provided key and KSN</returns>
        private static BigInteger GenerateKey(BigInteger key, BigInteger ksn)
        {
            return EncryptRegister(key ^ KeyMask, ksn) << 64 | EncryptRegister(key, ksn);
        }

        /// <summary>
        /// Encrypt Register
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="reg8">Register which to encrypt</param>
        /// <returns>Encrypted register value</returns>
        private static BigInteger EncryptRegister(BigInteger key, BigInteger reg8)
        {
            return (key & Ls16Mask) ^ Transform("DES", true, (key & Ms16Mask) >> 64, (key & Ls16Mask ^ reg8));
        }

        /// <summary>
        /// Transform Data
        /// </summary>
        /// <param name="name">Encryption algorithm name</param>
        /// <param name="encrypt">Encrypt data flag</param>
        /// <param name="key">Encryption key</param>
        /// <param name="message">Data to encrypt or decrypt</param>
        /// <returns>Result of transformation (encryption or decryption)</returns>
        private static BigInteger Transform(string name, bool encrypt, BigInteger key, BigInteger message)
        {
            using (SymmetricAlgorithm cipher = SymmetricAlgorithm.Create(name))
            {
                byte[] k = key.GetBytes();
                cipher.Key = new byte[Math.Max(0, GetNearestWholeMultiple(k.Length, 8) - k.Length)].Concat(key.GetBytes()).ToArray();
                cipher.IV = new byte[8];
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.Zeros;
                using (ICryptoTransform crypto = encrypt ? cipher.CreateEncryptor() : cipher.CreateDecryptor())
                {
                    byte[] data = message.GetBytes();
                    data = new byte[Math.Max(0, GetNearestWholeMultiple(data.Length, 8) - data.Length)].Concat(message.GetBytes()).ToArray();
                    return crypto.TransformFinalBlock(data, 0, data.Length).ToBigInteger();
                }
            }
        }

        /// <summary>
        /// Get nearest whole value of provided decimal value which is a multiple of provided integer
        /// </summary>
        /// <param name="input">Number which to determine nearest whole multiple</param>
        /// <param name="multiple">Multiple in which to divide input</param>
        /// <returns>Whole integer value of input nearest to a multiple of provided decimal</returns>
        private static int GetNearestWholeMultiple(decimal input, int multiple)
        {
            decimal output = Math.Round(input / multiple);
            if (output == 0 && input > 0)
            {
                output += 1;
            }
            output *= multiple;
            return (int)output;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Encrypt data using TDES DUKPT.
        /// </summary>
        /// <param name="bdk">Base Derivation Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <param name="data">Data to encrypt</param>
        /// <param name="variant">DUKPT transaction key variant</param>
        /// <returns>Encrypted data</returns>
        /// <exception cref="ArgumentNullException">Thrown for null or empty parameter values</exception>
        public static byte[] Encrypt(string bdk, string ksn, byte[] data, DukptVariant variant = DukptVariant.PIN)
        {
            if (string.IsNullOrEmpty(bdk))
            {
                throw new ArgumentNullException(nameof(bdk));
            }
            if (string.IsNullOrEmpty(ksn))
            {
                throw new ArgumentNullException(nameof(ksn));
            }
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            return Transform("TripleDES", true, CreateSessionKey(bdk, ksn, variant), data.ToBigInteger()).GetBytes();
        }

        /// <summary>
        /// Decrypt data using TDES DUKPT.
        /// </summary>
        /// <param name="bdk">Base Derivation Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <param name="data">Data to decrypt</param>
        /// <param name="variant">DUKPT transaction key variant</param>
        /// <returns>Decrypted data</returns>
        /// <exception cref="ArgumentNullException">Thrown for null or empty parameter values</exception>
        public static byte[] Decrypt(string bdk, string ksn, byte[] encryptedData, DukptVariant variant = DukptVariant.PIN)
        {
            if (string.IsNullOrEmpty(bdk))
            {
                throw new ArgumentNullException(nameof(bdk));
            }
            if (string.IsNullOrEmpty(ksn))
            {
                throw new ArgumentNullException(nameof(ksn));
            }
            if (encryptedData == null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

            return Transform("TripleDES", false, CreateSessionKey(bdk, ksn, variant), encryptedData.ToBigInteger()).GetBytes();
        }

        /// <summary>
        /// Decrypt data using TDES DUKPT Data variant.
        /// Backwards-compatible with previous versions of Dukpt.NET.
        /// </summary>
        /// <param name="bdk">Base Derivation Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <param name="data">Data to decrypt</param>
        /// <returns>Decrypted data</returns>
        public static byte[] DecryptIdTech(string bdk, string ksn, byte[] encryptedData)
        {
            return Decrypt(bdk, ksn, encryptedData, DukptVariant.Data);
        }

        #endregion

    }
}
