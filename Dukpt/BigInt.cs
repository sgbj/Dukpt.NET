using System;
using System.Linq;

namespace DukptSharp
{
    public class BigInt : IComparable<BigInt>
    {
        public byte[] Bytes { get; set; }

        public BigInt(byte[] bytes)
        {
            Bytes = bytes;
        }

        public BigInt(string hex)
        {
            Bytes = new byte[hex.Length / 2];
            for (var i = 0; i < Bytes.Length; i++)
                Bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }

        public BigInt Segment(int off, int len)
        {
            var b = new byte[len];
            Array.Copy(Bytes, off, b, Math.Max(0, len - Bytes.Length - off), Math.Min(len, Bytes.Length - off));
            return new BigInt(b);
        }

        public static BigInt operator |(BigInt a, BigInt b)
        {
            var len = Math.Max(a.Bytes.Length, b.Bytes.Length);
            return new BigInt(a.Segment(0, len).Bytes.Zip(b.Segment(0, len).Bytes, (x, y) => (byte)(x | y)).SkipWhile(n => n == 0).ToArray());
        }

        public static BigInt operator &(BigInt a, BigInt b)
        {
            var len = Math.Max(a.Bytes.Length, b.Bytes.Length);
            return new BigInt(a.Segment(0, len).Bytes.Zip(b.Segment(0, len).Bytes, (x, y) => (byte)(x & y)).SkipWhile(n => n == 0).ToArray());
        }

        public static BigInt operator ^(BigInt a, BigInt b)
        {
            var len = Math.Max(a.Bytes.Length, b.Bytes.Length);
            return new BigInt(a.Segment(0, len).Bytes.Zip(b.Segment(0, len).Bytes, (x, y) => (byte)(x ^ y)).SkipWhile(n => n == 0).ToArray());
        }

        public static BigInt operator >>(BigInt a, int n)
        {
            var nInts = n >> 3;
            var nBits = n & 7;
            var magLen = a.Bytes.Length;
            byte[] newMag = null;
            if (nInts >= magLen)
            {
                return new BigInt(new byte[1]);
            }
            var i = 0;
            var highBits = (byte)(a.Bytes[0] >> nBits);
            if (highBits != 0)
            {
                newMag = new byte[magLen - nInts];
                newMag[i++] = highBits;
            }
            else
            {
                newMag = new byte[magLen - nInts - 1];
            }
            var nBits2 = 8 - nBits;
            var j = 0;
            while (j < magLen - nInts - 1)
            {
                newMag[i++] = (byte)((a.Bytes[j++] << nBits2) | (a.Bytes[j] >> nBits));
            }
            return new BigInt(newMag);
        }


        public static BigInt operator <<(BigInt a, int n)
        {
            var nInts = n >> 3;
            var nBits = n & 7;
            var magLen = a.Bytes.Length;
            byte[] newMag = null;
            var i = 0;
            var nBits2 = 8 - nBits;
            var highBits = a.Bytes[0] >> nBits2;
            if (highBits != 0)
            {
                newMag = new byte[magLen + nInts + 1];
                newMag[i++] = (byte)highBits;
            }
            else
            {
                newMag = new byte[magLen + nInts];
            }
            var j = 0;
            while (j < magLen - 1)
            {
                newMag[i++] = (byte)(a.Bytes[j++] << nBits | a.Bytes[j] >> nBits2);
            }
            newMag[i] = (byte)(a.Bytes[j] << nBits);
            return new BigInt(newMag);
        }

        public static bool operator >(BigInt a, int b)
        {
            return a.CompareTo(new BigInt(BitConverter.GetBytes(b))) == 1;
        }

        public static bool operator <(BigInt a, int b)
        {
            return a.CompareTo(new BigInt(BitConverter.GetBytes(b))) == -1;
        }

        public override string ToString()
        {
            return BitConverter.ToString(Bytes).Replace("-", "");
        }

        public int CompareTo(BigInt other)
        {
            var m1 = Bytes.SkipWhile(b => b == 0).ToArray();
            var len1 = m1.Length;
            var m2 = other.Bytes.SkipWhile(b => b == 0).ToArray();
            var len2 = m2.Length;
            if (len1 < len2)
                return -1;
            if (len1 > len2)
                return 1;
            for (int i = 0; i < len1; i++)
            {
                int a = m1[i];
                int b = m2[i];
                if (a != b)
                    return a < b ? -1 : 1;
            }
            return 0;
        }
    }
}
