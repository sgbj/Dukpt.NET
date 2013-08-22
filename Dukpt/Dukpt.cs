using System.IO;
using System.Text;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace DukptSharp
{
    public class Dukpt
    {
        private static readonly BigInteger Reg3Mask     = BigInt.FromHex("1FFFFF");
        private static readonly BigInteger ShiftRegMask = BigInt.FromHex("100000");
        private static readonly BigInteger Reg8Mask     = BigInt.FromHex("FFFFFFFFFFE00000");
        private static readonly BigInteger Ls16Mask     = BigInt.FromHex("FFFFFFFFFFFFFFFF");
        private static readonly BigInteger Ms16Mask     = BigInt.FromHex("FFFFFFFFFFFFFFFF0000000000000000");
        private static readonly BigInteger KeyMask      = BigInt.FromHex("C0C0C0C000000000C0C0C0C000000000");
        private static readonly BigInteger PekMask      = BigInt.FromHex("FF00000000000000FF");
        private static readonly BigInteger KsnMask      = BigInt.FromHex("FFFFFFFFFFFFFFE00000");

        public static BigInteger CreateBdk(BigInteger key1, BigInteger key2)
        {
            return key1 ^ key2;
        }

        public static BigInteger CreateIpek(BigInteger ksn, BigInteger bdk)
        {
            return Encrypt("TripleDES", true, bdk, (ksn & KsnMask) >> 16) << 64 
                 | Encrypt("TripleDES", true, bdk ^ KeyMask, (ksn & KsnMask) >> 16);
        }

        public static BigInteger CreatePek(BigInteger ipek, BigInteger ksn)
        {
            return DeriveKey(ipek, ksn) ^ PekMask;
        }

        public static BigInteger DeriveKey(BigInteger ipek, BigInteger ksn)
        {
            var ksnReg = ksn & Ls16Mask & Reg8Mask;
            var curKey = ipek;
            for (var shiftReg = ShiftRegMask; shiftReg > 0; shiftReg >>= 1)
            {
                if ((shiftReg & ksn & Reg3Mask) > 0)
                {
                    ksnReg |= shiftReg;
                    curKey = GenerateKey(curKey, ksnReg);
                }
            }
            return curKey;
        }

        public static BigInteger GenerateKey(BigInteger key, BigInteger ksn)
        {
            return EncryptRegister(key ^ KeyMask, ksn) << 64 | EncryptRegister(key, ksn);
        }

        public static BigInteger EncryptRegister(BigInteger curKey, BigInteger reg8)
        {
            return (curKey & Ls16Mask) ^ Encrypt("DES", true, (curKey & Ms16Mask) >> 64, (curKey & Ls16Mask ^ reg8));
        }

        public static BigInteger Encrypt(string name, bool encrypt, BigInteger key, BigInteger message)
        {
            using (var cipher = SymmetricAlgorithm.Create(name))
            {
                cipher.Key = key.GetBytes();
                cipher.IV = new byte[8];
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.Zeros;
                using (var crypto = encrypt ? cipher.CreateEncryptor() : cipher.CreateDecryptor())
                using (var ms = new MemoryStream())
                {
                    var data = message.GetBytes();
                    BigInteger x = 0;
                    for (var i = 0; i < data.Length / 8; i++)
                    {
                        var bi = BigInt.FromBytes(message.GetBytes().Skip(i * 8).Take(8).ToArray());
                        if (encrypt)
                        {
                            bi = BigInt.FromBytes(crypto.TransformFinalBlock((bi ^ x).GetBytes(), 0, 8));
                            x = bi;
                        }
                        else
                        {
                            var y = bi;
                            bi = BigInt.FromBytes(crypto.TransformFinalBlock(bi.GetBytes(), 0, 8)) ^ x;
                            x = y;
                        }
                        var biData = bi.GetBytes();
                        ms.Write(biData, 0, biData.Length);
                    }
                    return BigInt.FromBytes(ms.ToArray());
                }
            }
        }

        public static byte[] Encrypt(string bdk, string ksn, byte[] track, bool encrypt = true)
        {
            var ipek = Dukpt.CreateIpek(BigInt.FromHex(ksn), BigInt.FromHex(bdk));
            var pek = Dukpt.CreatePek(ipek, BigInt.FromHex(ksn));
            var encrypted = Dukpt.Encrypt("TripleDES", encrypt, pek, BigInt.FromBytes(track));
            return encrypted.GetBytes();
        }
    }
}