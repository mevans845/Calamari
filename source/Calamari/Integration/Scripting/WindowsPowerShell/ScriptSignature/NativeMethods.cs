using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Calamari.Integration.Scripting.WindowsPowerShell.ScriptSignature
{
    internal class NativeMethods
    {
        public enum SigningOption
        {
            AddFullCertificateChain,
            AddFullCertificateChainExceptRoot,
            AddOnlyCertificate,
            Default
        }
        static uint GetCertChoiceFromSigningOption(SigningOption option)
        {
            uint num;
            switch (option)
            {
                case SigningOption.AddOnlyCertificate:
                    num = 0U;
                    break;
                case SigningOption.AddFullCertificateChain:
                    num = 1U;
                    break;
                case SigningOption.AddFullCertificateChainExceptRoot:
                    num = 2U;
                    break;
                default:
                    num = 2U;
                    break;
            }
            return num;
        }

        /// <summary>
        /// https://technet.microsoft.com/cs-cz/sysinternals/aa380676
        /// </summary>
        internal struct CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO
        {
            internal uint dwSize;
            internal uint dwAttrFlags;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszDescription;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszMoreInfoLocation;
            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszHashAlg;
            internal IntPtr pwszSigningCertDisplayString;
            internal IntPtr hAdditionalCertStore;
            internal IntPtr psAuthenticated;
            internal IntPtr psUnauthenticated;
        }

        /// <summary>
        /// https://technet.microsoft.com/cs-cz/sysinternals/aa380672
        /// </summary>
        internal struct CRYPTUI_WIZ_DIGITAL_SIGN_INFO
        {
            internal uint dwSize;
            internal uint dwSubjectChoice;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszFileName;
            internal uint dwSigningCertChoice;
            internal IntPtr pSigningCertContext;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszTimestampURL;
            internal uint dwAdditionalCertChoice;
            internal IntPtr pSignExtInfo;
        }

        internal struct CERT_ENHKEY_USAGE
        {
            internal uint cUsageIdentifier;
            internal IntPtr rgpszUsageIdentifier;
        }

        static CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO InitSignInfoExtendedStruct(string description, string moreInfoUrl, string hashAlgorithm)
        {
            var signExtendedInfo = new CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO();
            signExtendedInfo.dwSize = (uint)Marshal.SizeOf(signExtendedInfo);
            signExtendedInfo.dwAttrFlags = 0U;
            signExtendedInfo.pwszDescription = description;
            signExtendedInfo.pwszMoreInfoLocation = moreInfoUrl;
            signExtendedInfo.pszHashAlg = null;
            signExtendedInfo.pwszSigningCertDisplayString = IntPtr.Zero;
            signExtendedInfo.hAdditionalCertStore = IntPtr.Zero;
            signExtendedInfo.psAuthenticated = IntPtr.Zero;
            signExtendedInfo.psUnauthenticated = IntPtr.Zero;
            if (hashAlgorithm != null)
                signExtendedInfo.pszHashAlg = hashAlgorithm;
            return signExtendedInfo;
        }

        internal static CRYPTUI_WIZ_DIGITAL_SIGN_INFO InitSignInfoStruct(string fileName, X509Certificate2 signingCert, string timeStampServerUrl, string hashAlgorithm, SigningOption option)
        {
            var wizDigitalSignInfo = new CRYPTUI_WIZ_DIGITAL_SIGN_INFO();
            wizDigitalSignInfo.dwSize = (uint)Marshal.SizeOf(wizDigitalSignInfo);
            wizDigitalSignInfo.dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE;
            wizDigitalSignInfo.pwszFileName = fileName;
            wizDigitalSignInfo.dwSigningCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_CERT;
            wizDigitalSignInfo.pSigningCertContext = signingCert.Handle;
            wizDigitalSignInfo.pwszTimestampURL = timeStampServerUrl;
            wizDigitalSignInfo.dwAdditionalCertChoice = GetCertChoiceFromSigningOption(option);

            var signExtendedInfo = InitSignInfoExtendedStruct("", "", hashAlgorithm);
            IntPtr ptr = Marshal.AllocCoTaskMem(Marshal.SizeOf(signExtendedInfo));
            Marshal.StructureToPtr(signExtendedInfo, ptr, false);
            wizDigitalSignInfo.pSignExtInfo = ptr;
            return wizDigitalSignInfo;
        }

        /// <summary>
        /// The file specified by the pwszFileName member is to be signed.
        /// </summary>
        const uint CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE = 1U;

        /// <summary>
        /// The certificate is contained in the CERT_CONTEXT structure pointed to by the pSigningCertContext member
        /// </summary>
        const uint CRYPTUI_WIZ_DIGITAL_SIGN_CERT = 1U;

        internal const uint CRYPTUI_WIZ_NO_UI = 1U;

        [DllImport("cryptUI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptUIWizDigitalSign(uint dwFlags, IntPtr hwndParentNotUsed, IntPtr pwszWizardTitleNotUsed, IntPtr pDigitalSignInfo, IntPtr ppSignContextNotUsed);

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertGetEnhancedKeyUsage(IntPtr pCertContext, uint dwFlags, IntPtr pUsage, out int pcbUsage);

        [DllImport("crypt32.dll")]
        internal static extern IntPtr CryptFindOIDInfo(uint dwKeyType, IntPtr pvKey, uint dwGroupId);


        /// <summary>
        /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa381435(v=vs.85).aspx
        /// </summary>
        internal struct CRYPT_OID_INFO
        {
            public uint cbSize;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszOID;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszName;
            public uint dwGroupId;
            public Anonymous_a3ae7823_8a1d_432c_bc07_a72b6fc6c7d8 Union1;
            public CRYPT_ATTR_BLOB ExtraInfo;
        }

        /// <summary>
        /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa381414(v=vs.85).aspx
        /// </summary>
        internal struct CRYPT_ATTR_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct Anonymous_a3ae7823_8a1d_432c_bc07_a72b6fc6c7d8
        {
            [FieldOffset(0)]
            public uint dwValue;
            [FieldOffset(0)]
            public uint Algid;
            [FieldOffset(0)]
            public uint dwLength;
        }
    }

}
