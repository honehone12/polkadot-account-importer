using System.Text;
using PolkadotAccountImporter;
using SmoldotSharp.JsonRpc;

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
            const string path = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.json";

            Console.WriteLine($"Read a file {path}.");

            var pass = Encoding.UTF8.GetBytes("XXXXXXXXXX");
            var bytes = File.ReadAllBytes(path);
            var (ok, account) = AccountImporter.TryImport(bytes, pass);
            Assert(ok);

            var data = Encoding.UTF8.GetBytes("TestDataToSign");
            (ok, var key) = KeyPair.New(account.GetPublicKey, account.GetPrivateKey);
            Assert(ok);

            Console.WriteLine("pri");
            var pri = account.GetPrivateKey;
            for (int i = 0; i < pri.Length; i++)
            {
                Console.Write(pri[i]);
                Console.Write(",");
            }
            Console.WriteLine();

            Console.WriteLine("pub");
            var pub = account.GetPublicKey;
            for (int i = 0; i < pub.Length; i++)
            {
                Console.Write(pub[i]);
                Console.Write(",");
            }
            Console.WriteLine();

            var sig = Signer.Sign(data, key);
            var s = sig.GetSignature;
            Console.WriteLine("sig");
            for (int i = 0; i < s.Length; i++)
            {
                Console.Write(s[i]);
                Console.Write(",");
            }
            Console.WriteLine();
        }
    }
}