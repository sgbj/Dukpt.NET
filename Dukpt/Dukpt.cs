using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace DukptSharp
{
    public static class Dukpt
    {
        private static readonly BigInteger Reg3Mask = BigInt.FromHex("1FFFFF");
        private static readonly BigInteger ShiftRegMask = BigInt.FromHex("100000");
        private static readonly BigInteger Reg8Mask = BigInt.FromHex("FFFFFFFFFFE00000");
        private static readonly BigInteger Ls16Mask = BigInt.FromHex("FFFFFFFFFFFFFFFF");
        private static readonly BigInteger Ms16Mask = BigInt.FromHex("FFFFFFFFFFFFFFFF0000000000000000");
        private static readonly BigInteger KeyMask = BigInt.FromHex("C0C0C0C000000000C0C0C0C000000000");
        private static readonly BigInteger PekMask = BigInt.FromHex("FF00000000000000FF");
        private static readonly BigInteger KsnMask = BigInt.FromHex("FFFFFFFFFFFFFFE00000");

        public static BigInteger CreateBdk(BigInteger key1, BigInteger key2)
        {
            return key1 ^ key2;
        }

        public static BigInteger CreateIpek(BigInteger ksn, BigInteger bdk)
        {
            return Transform("TripleDES", true, bdk, (ksn & KsnMask) >> 16) << 64
                 | Transform("TripleDES", true, bdk ^ KeyMask, (ksn & KsnMask) >> 16);
        }

        public static BigInteger CreateSessionKey(BigInteger ipek, BigInteger ksn)
        {
            return DeriveKey(ipek, ksn) ^ PekMask;
        }

        public static BigInteger DeriveKey(BigInteger ipek, BigInteger ksn)
        {
            var ksnReg = ksn & Ls16Mask & Reg8Mask;
            var curKey = ipek;
            for (var shiftReg = ShiftRegMask; shiftReg > 0; shiftReg >>= 1)
                if ((shiftReg & ksn & Reg3Mask) > 0)
                    curKey = GenerateKey(curKey, ksnReg |= shiftReg);
            return curKey;
        }

        public static BigInteger GenerateKey(BigInteger key, BigInteger ksn)
        {
            return EncryptRegister(key ^ KeyMask, ksn) << 64 | EncryptRegister(key, ksn);
        }

        public static BigInteger EncryptRegister(BigInteger curKey, BigInteger reg8)
        {
            return (curKey & Ls16Mask) ^ Transform("DES", true, (curKey & Ms16Mask) >> 64, (curKey & Ls16Mask ^ reg8));
        }

        public static BigInteger Transform(string name, bool encrypt, BigInteger key, BigInteger message)
        {
            using (var cipher = SymmetricAlgorithm.Create(name))
            {
                // Bug - https://github.com/sgbj/Dukpt.NET/issues/5 - Specified key is not a valid size for this algorithm.
                // I usually trim the zero-bytes off the front of the array in the GetBytes method, 
                // but this algorithm expects either 8 or 16 byte keys, so GetBytes will occasionally return 7.
                var k = key.GetBytes();
                cipher.Key = new byte[Math.Max(0, 8 - k.Length)].Concat(key.GetBytes()).ToArray();
                cipher.IV = new byte[8];
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.Zeros;
                using (var crypto = encrypt ? cipher.CreateEncryptor() : cipher.CreateDecryptor())
                {
                    var data = message.GetBytes();
                    return BigInt.FromBytes(crypto.TransformFinalBlock(data, 0, data.Length));
                }
            }
        }

        public static byte[] Encrypt(string bdk, string ksn, byte[] track)
        {
            return Transform("TripleDES", true, CreateSessionKey(CreateIpek(
                BigInt.FromHex(ksn), BigInt.FromHex(bdk)), BigInt.FromHex(ksn)), BigInt.FromBytes(track)).GetBytes();
        }

        public static byte[] Decrypt(string bdk, string ksn, byte[] track)
        {
            return Transform("TripleDES", false, CreateSessionKey(CreateIpek(
                BigInt.FromHex(ksn), BigInt.FromHex(bdk)), BigInt.FromHex(ksn)), BigInt.FromBytes(track)).GetBytes();
        }
    }
}
