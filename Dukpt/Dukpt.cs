using System.IO;
using System.Security.Cryptography;

namespace DukptSharp
{
    public class Dukpt
    {
        static BigInt REG3_MASK = new BigInt("1FFFFF");
        static BigInt SHIFT_REG_MASK = new BigInt("100000");
        static BigInt REG8_MASK = new BigInt("FFFFFFFFFFE00000");
        static BigInt LS16_MASK = new BigInt("FFFFFFFFFFFFFFFF");
        static BigInt MS16_MASK = new BigInt("FFFFFFFFFFFFFFFF0000000000000000");
        static BigInt KEY_MASK = new BigInt("C0C0C0C000000000C0C0C0C000000000");
        static BigInt PEK_MASK = new BigInt("FF00000000000000FF");
        static BigInt KSN_MASK = new BigInt("FFFFFFFFFFFFFFE00000");

        public static BigInt CreateBdk(BigInt key1, BigInt key2)
        {
            return key1 ^ key2;
        }

        public static BigInt CreateIpek(BigInt ksn, BigInt bdk)
        {
            return Encrypt((ksn & KSN_MASK) >> 16, bdk) << 64 | Encrypt((ksn & KSN_MASK) >> 16, bdk ^ KEY_MASK);
        }

        public static BigInt CreatePek(BigInt ipek, BigInt ksn)
        {
            return DeriveKey(ipek, ksn) ^ PEK_MASK;
        }

        public static BigInt DeriveKey(BigInt ipek, BigInt ksn)
        {
            var ksnReg = ksn & LS16_MASK & REG8_MASK;
            var curKey = ipek;
            for (var shiftReg = SHIFT_REG_MASK; shiftReg > 0; shiftReg >>= 1)
            {
                if ((shiftReg & ksn & REG3_MASK) > 0)
                {
                    ksnReg |= shiftReg;
                    curKey = Keygen(curKey, ksnReg);
                }
            }
            return curKey;
        }

        public static BigInt Keygen(BigInt key, BigInt ksn)
        {
            return EncryptRegister(key ^ KEY_MASK, ksn) << 64 | EncryptRegister(key, ksn);
        }

        public static BigInt EncryptRegister(BigInt curKey, BigInt reg8)
        {
            return (curKey & LS16_MASK) ^ Encrypt("DES", true, (curKey & MS16_MASK) >> 64, (curKey & LS16_MASK ^ reg8));
        }

        public static BigInt Encrypt(string name, bool encrypt, BigInt key, BigInt message)
        {
            using (var cipher = SymmetricAlgorithm.Create(name))
            {
                System.Console.WriteLine("COOL " + key.Bytes.Length + " ~ " + message.Bytes.Length);
                System.Console.WriteLine("DATA " + key + " ~ " + message);

                cipher.Key = key.Bytes;
                cipher.IV = new byte[8];
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.Zeros;
                using (var crypto = encrypt ? cipher.CreateEncryptor() : cipher.CreateDecryptor())
                using (var ms = new MemoryStream())
                {
                    for (var i = 0; i < message.Bytes.Length / 8; i++)
                    {
                        var bi = new BigInt(crypto.TransformFinalBlock(message.Segment(i * 8, 8).Bytes, 0, 8));
                        bi = i == 0 ? bi : (bi ^ message.Segment((i - 1) * 8, 8));
                        ms.Write(bi.Bytes, 0, bi.Bytes.Length);
                    }
                    return new BigInt(ms.ToArray());
                }
            }
        }

        public static BigInt Encrypt(BigInt b, BigInt key)
        {
            using (var cipher = TripleDES.Create())
            {
                System.Console.WriteLine("COOL2 " + key.Bytes.Length + " ~ " + b.Bytes.Length);
                System.Console.WriteLine("DATA2 " + key + " ~ " + b);

                cipher.Key = key.Bytes;
                cipher.IV = new byte[8];
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.Zeros;
                using (var crypto = cipher.CreateEncryptor())
                {
                    return new BigInt(crypto.TransformFinalBlock(b.Bytes, 0, b.Bytes.Length));
                }
            }
        }
    }
}