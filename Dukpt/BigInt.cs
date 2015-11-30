using System.Linq;
using System.Numerics;

namespace DukptNet
{
    public static class BigInt
    {

        public static BigInteger FromHex(string hex)
        {
            return BigInteger.Parse("00" + hex, System.Globalization.NumberStyles.HexNumber);
        }

        public static BigInteger FromBytes(byte[] bytes)
        {
            return new BigInteger(bytes.Reverse().Concat(new byte[] { 0 }).ToArray());
        }

        public static byte[] GetBytes(this BigInteger number)
        {
            return number.ToByteArray().Reverse().SkipWhile(b => b == 0).ToArray();
        }
    }
}