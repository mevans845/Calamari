using System;
using System.Security.Cryptography.X509Certificates;

namespace Calamari.Integration.Scripting.WindowsPowerShell.ScriptSignature
{
    public class ScriptSigner
    {
        public void SignFile(string fileName, string certificateSubject)
        {
            var my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);

            foreach (var cert in my.Certificates)
            {
                if (cert.Subject.Contains(certificateSubject))
                {
                    SignatureHelper.SignFile(fileName, cert);
                    return;
                }
            }
            throw new Exception("No valid cert was found");
        }
    }
}
