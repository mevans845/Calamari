using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Calamari.Integration.Scripting.WindowsPowerShell.ScriptSignature
{
    internal class SecuritySupport
    {
        internal static bool CertIsGoodForSigning(X509Certificate2 c)
        {
            if (!SecuritySupport.CertHasPrivatekey(c))
                return false;
            return SecuritySupport.CertHasOid(c, "1.3.6.1.5.5.7.3.3");
        }

        internal static bool CertHasPrivatekey(X509Certificate2 cert)
        {
            return cert.HasPrivateKey;
        }

        private static bool CertHasOid(X509Certificate2 c, string oid)
        {
            foreach (string str in SecuritySupport.GetCertEKU(c))
            {
                if (str == oid)
                    return true;
            }
            return false;
        }

        internal static Collection<string> GetCertEKU(X509Certificate2 cert)
        {
            Collection<string> collection = new Collection<string>();
            IntPtr handle = cert.Handle;
            int pcbUsage = 0;
            IntPtr pUsage = IntPtr.Zero;
            if (!NativeMethods.CertGetEnhancedKeyUsage(handle, 0U, pUsage, out pcbUsage))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (pcbUsage > 0)
            {
                IntPtr num = Marshal.AllocHGlobal(pcbUsage);
                try
                {
                    if (!NativeMethods.CertGetEnhancedKeyUsage(handle, 0U, num, out pcbUsage))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    NativeMethods.CERT_ENHKEY_USAGE certEnhkeyUsage = (NativeMethods.CERT_ENHKEY_USAGE)Marshal.PtrToStructure(num, typeof(NativeMethods.CERT_ENHKEY_USAGE));
                    IntPtr ptr = certEnhkeyUsage.rgpszUsageIdentifier;
                    for (int index = 0; (long)index < (long)certEnhkeyUsage.cUsageIdentifier; ++index)
                    {
                        string str = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(ptr, index * Marshal.SizeOf((object)ptr)));
                        collection.Add(str);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(num);
                }
            }
            return collection;
        }
    }
}
