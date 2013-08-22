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
            // Test 1
            var bdk = new BigInt("0123456789ABCDEFFEDCBA9876543210");
            var ksn = new BigInt("FFFF9876543210E00008");
            var track = new BigInt("C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12");
            var ipek = Dukpt.CreateIpek(ksn, bdk);
            var pek = Dukpt.CreatePek(ipek, ksn);
            var decrypted = Dukpt.Encrypt("TripleDES", false, pek, track);
            Console.WriteLine(UTF8Encoding.UTF8.GetString(decrypted.Bytes));
            // Test 2
            track = new BigInt("693B0FB71F414FA7771269499469D5A41267EA33E43F343973D1483CA1B766963A02247A898E20F103F441917D3925E1EB1530FEA40D9233595367D6723C78EBD81893E1B3695436");
            ksn = new BigInt("9011060B0051B1000033");
            var keyComponent1 = new BigInt("0FD409BB44E80A82BD11CF60F9BBC53F");
            var keyComponent2 = new BigInt("E68051762352E64F495DA7BF46255D0B");
            bdk = Dukpt.CreateBdk(keyComponent1, keyComponent2);
            ipek = Dukpt.CreateIpek(ksn, bdk);
            pek = Dukpt.CreatePek(ipek, ksn);
            decrypted = Dukpt.Encrypt("TripleDES", false, pek, track);
            Console.WriteLine(UTF8Encoding.UTF8.GetString(decrypted.Bytes));
            Console.WriteLine(bdk);

        }
    }
}
