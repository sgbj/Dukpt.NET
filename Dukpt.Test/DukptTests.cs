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
        public static string _expectedEncryptedHexMAC = "264409351C558CA522A5A2B55CC68AFFA0AC490070F730C452171C43D42442CE1EFEEB60EF53BCD23FF8EB2081C7C27F487725D61EC94C1AD8781563E0C5BC";
        public static string _expectedEncryptedHexDEK = "411D405D7DEDB9D84797F045559721E8C06A5565FFB3B4050509277E5F80072E2410E0E6ADCBB614419700A9173807BA27C4E9D80BE67A2C32498032B200A7E3";

        #region PEK Mask Tests

        [TestMethod]
        public void Test_PEK_Encryption()
        {
            byte[] encryptedBytes = Dukpt.Encrypt(_bdk, _ksn, Encoding.UTF8.GetBytes(_clearData));
            string encryptedHexResult = BitConverter.ToString(encryptedBytes).Replace("-", "");
            Assert.AreEqual(encryptedHexResult, _expectedEncryptedHexPEK);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Encryption_Null_Data()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, _ksn, null, DukptVariants.PIN);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Encryption_Null_BDK()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(null, _ksn, Encoding.UTF8.GetBytes(_clearData), DukptVariants.PIN);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Encryption_Null_KSN()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, null, Encoding.UTF8.GetBytes(_clearData), DukptVariants.PIN);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Encryption_Empty_BDK()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(string.Empty, _ksn, Encoding.UTF8.GetBytes(_clearData), DukptVariants.PIN);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Encryption_Empty_KSN()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, string.Empty, Encoding.UTF8.GetBytes(_clearData), DukptVariants.PIN);
        }

        [TestMethod]
        public void Test_PEK_Decryption()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, _ksn, _expectedEncryptedHexPEK.HexStringToByteArray());
            string decryptedData = Encoding.UTF8.GetString(decryptedBytes);
            Assert.AreEqual(decryptedData, _clearData);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Decryption_Null_Data()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, _ksn, null, DukptVariants.PIN);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Decryption_Null_BDK()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(null, _ksn, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.PIN);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Decryption_Null_KSN()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, null, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.PIN);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Decryption_Empty_BDK()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(string.Empty, _ksn, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.PIN);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_PEK_Decryption_Empty_KSN()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, string.Empty, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.PIN);
        }

        #endregion

        #region MAC Mask Tests

        [TestMethod]
        public void Test_MAC_Encryption()
        {
            byte[] encryptedBytes = Dukpt.Encrypt(_bdk, _ksn, Encoding.UTF8.GetBytes(_clearData), DukptVariants.MAC);
            string encryptedHexResult = BitConverter.ToString(encryptedBytes).Replace("-", "");
            Assert.AreEqual(encryptedHexResult, _expectedEncryptedHexMAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Encryption_Null_Data()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, _ksn, null, DukptVariants.MAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Encryption_Null_BDK()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(null, _ksn, Encoding.UTF8.GetBytes(_clearData), DukptVariants.MAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Encryption_Null_KSN()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, null, Encoding.UTF8.GetBytes(_clearData), DukptVariants.MAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Encryption_Empty_BDK()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(string.Empty, _ksn, Encoding.UTF8.GetBytes(_clearData), DukptVariants.MAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Encryption_Empty_KSN()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, string.Empty, Encoding.UTF8.GetBytes(_clearData), DukptVariants.MAC);
        }

        [TestMethod]
        public void Test_MAC_Decryption()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, _ksn, _expectedEncryptedHexMAC.HexStringToByteArray(), DukptVariants.MAC);
            string decryptedData = Encoding.UTF8.GetString(decryptedBytes);
            Assert.AreEqual(decryptedData, _clearData);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Decryption_Null_Data()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, _ksn, null, DukptVariants.MAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Decryption_Null_BDK()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(null, _ksn, _expectedEncryptedHexMAC.HexStringToByteArray(), DukptVariants.MAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Decryption_Null_KSN()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, null, _expectedEncryptedHexMAC.HexStringToByteArray(), DukptVariants.MAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Decryption_Empty_BDK()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(string.Empty, _ksn, _expectedEncryptedHexMAC.HexStringToByteArray(), DukptVariants.MAC);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_MAC_Decryption_Empty_KSN()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, string.Empty, _expectedEncryptedHexMAC.HexStringToByteArray(), DukptVariants.MAC);
        }

        #endregion


        #region DEK Mask Tests

        [TestMethod]
        public void Test_DEK_Encryption()
        {
            byte[] encryptedBytes = Dukpt.Encrypt(_bdk, _ksn, Encoding.UTF8.GetBytes(_clearData), DukptVariants.Data);
            string encryptedHexResult = BitConverter.ToString(encryptedBytes).Replace("-", "");
            Assert.AreEqual(encryptedHexResult, _expectedEncryptedHexDEK);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Encryption_Null_Data()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, _ksn, null, DukptVariants.Data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Encryption_Null_BDK()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(null, _ksn, Encoding.UTF8.GetBytes(_clearData), DukptVariants.Data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Encryption_Null_KSN()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, null, Encoding.UTF8.GetBytes(_clearData), DukptVariants.Data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Encryption_Empty_BDK()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(string.Empty, _ksn, Encoding.UTF8.GetBytes(_clearData), DukptVariants.Data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Encryption_Empty_KSN()
        {
            byte[] decryptedBytes = Dukpt.Encrypt(_bdk, string.Empty, Encoding.UTF8.GetBytes(_clearData), DukptVariants.Data);
        }

        [TestMethod]
        public void Test_DEK_Decryption()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, _ksn, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.Data);
            string decryptedData = Encoding.UTF8.GetString(decryptedBytes);
            Assert.AreEqual(decryptedData, _clearData);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Decryption_Null_Data()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, _ksn, null, DukptVariants.Data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Decryption_Null_BDK()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(null, _ksn, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.Data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Decryption_Null_KSN()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, null, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.Data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Decryption_Empty_BDK()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(string.Empty, _ksn, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.Data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Test_DEK_Decryption_Empty_KSN()
        {
            byte[] decryptedBytes = Dukpt.Decrypt(_bdk, string.Empty, _expectedEncryptedHexDEK.HexStringToByteArray(), DukptVariants.Data);
        }

        #endregion

    }
}
