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

        #endregion

        #region Private Methods

        private static BigInteger CreateIpek(BigInteger ksn, BigInteger bdk)
        {
            return Transform("TripleDES", true, bdk, (ksn & KsnMask) >> 16) << 64
                 | Transform("TripleDES", true, bdk ^ KeyMask, (ksn & KsnMask) >> 16);
        }

        private static BigInteger CreateSessionKeyPEK(BigInteger ipek, BigInteger ksn)
        {
            return DeriveKey(ipek, ksn) ^ PekMask;
        }

        private static BigInteger CreateSessionKeyDEK(BigInteger ipek, BigInteger ksn) {
			var key = DeriveKey(ipek, ksn) ^ DekMask;
			return Transform("TripleDES", true, key, (key & Ms16Mask) >> 64) << 64 
				 | Transform("TripleDES", true, key, (key & Ls16Mask));
		}

        private static BigInteger CreateSessionKey(string bdk, string ksn, bool isPIN)
        {
            BigInteger ksnBigInt = ksn.HexToBigInteger();
            BigInteger ipek = CreateIpek(ksnBigInt, bdk.HexToBigInteger());
            BigInteger sessionKey = isPIN ? CreateSessionKeyPEK(ipek, ksnBigInt) : CreateSessionKeyDEK(ipek, ksnBigInt);
            return sessionKey;
        }

        private static BigInteger DeriveKey(BigInteger ipek, BigInteger ksn)
        {
            var ksnReg = ksn & Ls16Mask & Reg8Mask;
            var curKey = ipek;
            for (var shiftReg = ShiftRegMask; shiftReg > 0; shiftReg >>= 1)
                if ((shiftReg & ksn & Reg3Mask) > 0)
                    curKey = GenerateKey(curKey, ksnReg |= shiftReg);
            return curKey;
        }

        private static BigInteger GenerateKey(BigInteger key, BigInteger ksn)
        {
            return EncryptRegister(key ^ KeyMask, ksn) << 64 | EncryptRegister(key, ksn);
        }

        private static BigInteger EncryptRegister(BigInteger curKey, BigInteger reg8)
        {
            return (curKey & Ls16Mask) ^ Transform("DES", true, (curKey & Ms16Mask) >> 64, (curKey & Ls16Mask ^ reg8));
        }

        private static BigInteger Transform(string name, bool encrypt, BigInteger key, BigInteger message)
        {
            using (var cipher = SymmetricAlgorithm.Create(name))
            {
                var k = key.GetBytes();
                cipher.Key = new byte[Math.Max(0, GetNearestWholeMultiple(k.Length, 8) - k.Length)].Concat(key.GetBytes()).ToArray();
                cipher.IV = new byte[8];
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.Zeros;
                using (var crypto = encrypt ? cipher.CreateEncryptor() : cipher.CreateDecryptor())
                {
                    var data = message.GetBytes();
                    data = new byte[Math.Max(0, GetNearestWholeMultiple(data.Length, 8) - data.Length)].Concat(message.GetBytes()).ToArray();
                    return crypto.TransformFinalBlock(data, 0, data.Length).ToBigInteger();
                }
            }
        }

        private static int GetNearestWholeMultiple(decimal input, int multiple)
        {
            var output = Math.Round(input / multiple);
            if (output == 0 && input > 0) output += 1;
            output *= multiple;
            return (int)output;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Encrypt provided data using TDES DUKPT
        /// </summary>
        /// <param name="bdk">Base Derivation Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <param name="data">Data to encrypt</param>
        /// <param name="isPIN">Provided data is PIN data</param>
        /// <returns>Encrypted data</returns>
        public static byte[] Encrypt(string bdk, string ksn, byte[] data, bool isPIN = true)
        {
            return Transform("TripleDES", true, CreateSessionKey(bdk, ksn, isPIN), data.ToBigInteger()).GetBytes();
        }

        /// <summary>
        /// Decrypt provided data using TDES DUKPT
        /// </summary>
        /// <param name="bdk">Base Derivation Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <param name="data">Data to decrypt</param>
        /// <param name="isPIN">Provided data is PIN data</param>
        /// <returns>Decrypted data</returns>
        public static byte[] Decrypt(string bdk, string ksn, byte[] encryptedData, bool isPIN = true)
        {
            return Transform("TripleDES", false, CreateSessionKey(bdk, ksn, isPIN), encryptedData.ToBigInteger()).GetBytes();
        }

        /// <summary>
        /// Decrypt provided data using TDES DUKPT using DEK mask
        /// Backwards-compatible with previous versions of Dukpt.NET
        /// </summary>
        /// <param name="bdk">Base Derivation Key</param>
        /// <param name="ksn">Key Serial Number</param>
        /// <param name="data">Data to decrypt</param>
        /// <returns>Decrypted data</returns>
        public static byte[] DecryptIdTech(string bdk, string ksn, byte[] encryptedData)
        {
            return Decrypt(bdk, ksn, encryptedData, false);
        }

        #endregion

    }
}
