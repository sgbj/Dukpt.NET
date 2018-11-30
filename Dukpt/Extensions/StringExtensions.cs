using System.Numerics;

namespace DukptNet
{
    public static class StringExtensions
    {
        public static BigInteger HexToBigInteger(this string str)
        {
            return BigInteger.Parse("00" + str, System.Globalization.NumberStyles.HexNumber);
        }
    }
}
