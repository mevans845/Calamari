using System;
using System.Security.Cryptography.X509Certificates;
using Calamari.Integration.Certificates;

namespace Calamari.Integration.Scripting.WindowsPowerShell.ScriptSignature
{
    public class ScriptSigner
    {
        private readonly ICertificateStore certificateStore;

        public ScriptSigner(ICertificateStore certificateStore)
        {
            this.certificateStore = certificateStore;
        }

        string ScriptSignThumbprint
        {
            get
            {
                return "1B3E2E1E5A67DC7B4AB854F970671648852954C6";
                //return Environment.GetEnvironmentVariable("TentacleProxyPassword");
            }
        }

        string ScriptSignStore
        {
            get { return StoreName.My.ToString(); }
        }

        StoreLocation ScriptSignLocation
        {
            get { return StoreLocation.CurrentUser; }
        }

        public void SignFile(string fileName, string certificateSubject)
        {
            var cert = certificateStore.GetByThumbprint(ScriptSignThumbprint);
            SignatureHelper.SignFile(fileName, cert);
        }
    }
}
