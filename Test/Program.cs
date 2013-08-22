using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DukptSharp;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            var test = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

            // Decrypting
            var bdk = "0123456789ABCDEFFEDCBA9876543210";
            var ksn = "FFFF9876543210E00008";
            var track = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12";
            var decBytes = Dukpt.Encrypt(bdk, ksn, BigInt.FromHex(track).GetBytes(), false);
            var decrypted = UTF8Encoding.UTF8.GetString(decBytes);
            Console.WriteLine(decrypted == test);

            // Encrypting
            var encBytes = Dukpt.Encrypt(bdk, ksn, decBytes, true);
            var encrypted = BitConverter.ToString(encBytes).Replace("-", "");
            Console.WriteLine(encrypted == track);
        }
    }
}
