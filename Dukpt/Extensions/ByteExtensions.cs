using System.Linq;
using System.Numerics;

namespace DukptNet
{
    internal static class ByteExtensions
    {
        public static BigInteger ToBigInteger(this byte[] bytes)
        {
            return new BigInteger(bytes.Reverse().Concat(new byte[] { 0 }).ToArray());
        }
    }
}
