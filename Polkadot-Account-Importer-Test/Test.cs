using System.Diagnostics;
using System.Text;
using PolkadotAccountImporter;
using SmoldotSharp.JsonRpc;
using sr25519_dotnet.lib;

namespace PolkadotKeyImporterTest
{
    internal class Test
    {
        static void Assert(params bool[] checks)
        {
            for (int i = 0; i < checks.Length; i++)
            {
                if (!checks[i])
                {
                    throw new Exception("Test failed.");
                }
            }
        }

        static void Main(string[] args)
        {
            const string path = "MyAccount.json";

            Console.WriteLine($"Read a file {path}.");

            var pass = Encoding.UTF8.GetBytes("sobashochu");
            var bytes = File.ReadAllBytes(path);
            var (ok, account) = AccountImporter.TryImport(bytes, pass);
            Assert(ok);

            var msg = Encoding.UTF8.GetBytes("TestDataToSign");
            (ok, var key) = KeyPair.New(account.GetPublicKey, account.GetPrivateKey);
            Assert(ok);

            Console.WriteLine("pub");
            var pub = account.GetPublicKey;
            for (int i = 0; i < pub.Length; i++)
            {
                Console.Write(pub[i]);
                Console.Write(",");
            }
            Console.WriteLine();

            var sig = Signer.Sign(msg, key);

            ok = SR25519.Verify(msg, sig.GetSignature.ToArray(), pub);
            Assert(ok);
        }
    }
}