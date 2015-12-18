using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Calamari.Integration.Scripting.WindowsPowerShell.ScriptSignature
{
    internal class SignatureHelper
    {
        internal static void SignFile(string fileName, X509Certificate2 certificate, string timeStampServerUrl = null, string hashAlgorithm = null)
        {
            if (!string.IsNullOrEmpty(timeStampServerUrl) && (timeStampServerUrl.Length <= 7 || timeStampServerUrl.IndexOf("http://", StringComparison.OrdinalIgnoreCase) != 0))
                throw new ArgumentException("TimeStampUrlRequired");
            if (!string.IsNullOrEmpty(hashAlgorithm))
            {
                IntPtr oidInfo = NativeMethods.CryptFindOIDInfo(2U, Marshal.StringToHGlobalUni(hashAlgorithm), 0U);
                if (oidInfo == IntPtr.Zero)
                    throw new ArgumentException("InvalidHashAlgorithm");
                hashAlgorithm = ((NativeMethods.CRYPT_OID_INFO)Marshal.PtrToStructure(oidInfo, typeof(NativeMethods.CRYPT_OID_INFO))).pszOID;
            }
            if (!SecuritySupport.CertIsGoodForSigning(certificate))
                throw new ArgumentException("CertNotGoodForSigning");


            var wizDigitalSignInfo = NativeMethods.InitSignInfoStruct(fileName, certificate, timeStampServerUrl, hashAlgorithm, NativeMethods.SigningOption.AddOnlyCertificate);
            IntPtr num = IntPtr.Zero;
            try
            {
                num = Marshal.AllocCoTaskMem(Marshal.SizeOf(wizDigitalSignInfo));
                Marshal.StructureToPtr(wizDigitalSignInfo, num, false);
                var sign = NativeMethods.CryptUIWizDigitalSign(NativeMethods.CRYPTUI_WIZ_NO_UI, IntPtr.Zero, IntPtr.Zero,
                    num, IntPtr.Zero);
                if (sign)
                    return;

                var error = GetLastWin32Error();
                switch (error)
                {
                    case 2147500037U:
                    case 2147942401U:
                    case 2147954407U:
                        break;
                    case 2148073480U:
                        throw new ArgumentException("InvalidHashAlgorithm");
                    default:
                        throw new Exception(string.Format("CryptUIWizDigitalSign: failed: {0:x}", (object) error));
                }
            }
            finally
            {
                Marshal.DestroyStructure(num, typeof (NativeMethods.CRYPTUI_WIZ_DIGITAL_SIGN_INFO));
                Marshal.FreeCoTaskMem(num);
            }
        }

        private static uint GetLastWin32Error()
        {
            return GetDWORDFromInt(Marshal.GetLastWin32Error());
        }

        internal static uint GetDWORDFromInt(int n)
        {
            return BitConverter.ToUInt32(BitConverter.GetBytes(n), 0);
        }
    }
}
