using System;
using System.Text;
using DukptNet.Test.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DukptNet.Test
{
    [TestClass]
    public class DukptTests
    {

        public static string _ksn = "FFFF9876543210E00008";
        public static string _bdk = "0123456789ABCDEFFEDCBA9876543210";
        public static string _clearData = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";
        public static string _expectedEncryptedHexPEK = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12";
        public static string _expectedEncryptedHexDEK = "411D405D7DEDB9D84797F045559721E8C06A5565FFB3B4050509277E5F80072E2410E0E6ADCBB614419700A9173807BA27C4E9D80BE67A2C32498032B200A7E3";

        [TestMethod]
        public void TestEncryption_PEK_Mask()
        {
            byte[] encryptedBytes = Dukpt.Encrypt(_bdk, _ksn, Encoding.UTF8.GetBytes(_clearData));
            string encryptedHexResult = BitConverter.ToString(encryptedBytes).Replace("-", "");
            Assert.AreEqual(encryptedHexResult, _expectedEncryptedHexPEK);
        }

        [TestMethod]
        public void TestDecryption_PEK_Mask()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, _ksn, _expectedEncryptedHexPEK.HexStringToByteArray());
            string decryptedData = Encoding.UTF8.GetString(decryptedBytes);
            Assert.AreEqual(decryptedData, _clearData);
        }

        [TestMethod]
        public void TestEncryption_DEK_Mask()
        {
            byte[] encryptedBytes = Dukpt.Encrypt(_bdk, _ksn, Encoding.UTF8.GetBytes(_clearData), false);
            string encryptedHexResult = BitConverter.ToString(encryptedBytes).Replace("-", "");
            Assert.AreEqual(encryptedHexResult, _expectedEncryptedHexDEK);
        }

        [TestMethod]
        public void TestDecryption_DEK_Mask()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, _ksn, _expectedEncryptedHexDEK.HexStringToByteArray(), false);
            string decryptedData = Encoding.UTF8.GetString(decryptedBytes);
            Assert.AreEqual(decryptedData, _clearData);
        }

    }
}
