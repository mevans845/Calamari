using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Calamari.Integration.FileSystem;
using Calamari.Integration.Processes;
using Calamari.Integration.Scripting.WindowsPowerShell;
using NUnit.Framework;

namespace Calamari.Tests.Fixtures.Integration.Scripting.WindowsPowerShell
{
    [TestFixture]
    public class PowerShellBootstrapperFixture
    {
        [Test]
        public void DOIt()
        {
            using (var scriptFile = new TemporaryFile(Path.ChangeExtension(Path.GetTempFileName(), "ps1")))
            {
                File.WriteAllText(scriptFile.FilePath, "Write-Host $mysecrect");
                PowerShellBootstrapper.PrepareBootstrapFile(scriptFile.FilePath, new CalamariVariableDictionary());
            }
        }
    }
}
