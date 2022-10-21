using System;
using System.Text;
using System.Diagnostics;
using System.Linq;
using Newtonsoft.Json;
using CryptSharp.Utility;
using NaCl;

namespace PolkadotAccountImporter
{
    public static class AccountImporter
    {
        static bool IsAvailable(AccountEncoding encoding)
        {
            if (!encoding.version.Equals("3"))
            {
                return false;
            }

            if (!encoding.content.Contains("pkcs8") ||
                !encoding.content.Contains("sr25519"))
            {
                return false;
            }

            if (!encoding.type.Contains("scrypt") ||
                !encoding.type.Contains("xsalsa20-poly1305"))
            {
                return false;
            }

            return true;
        }

        public static (bool, ImportedAccount) TryImport(byte[] raw, byte[] passPhrase)
        {
            var rawStr = Encoding.UTF8.GetString(raw);
            var exportedAccount = JsonConvert.DeserializeObject<ExportedAccountFormat>(rawStr);
            if (exportedAccount == null)
            {
                Debug.Fail("file is not expected.");
                return (false, new ImportedAccount());
            }

            if (!IsAvailable(exportedAccount.encoding))
            {
                Debug.Fail("exported account encoding is not supported.");
                return (false, new ImportedAccount());
            }

            const int DefaultN = 32768;
            const int DefaultP = 1;
            const int DefaultR = 8;
            const int DKLen = 32;
            const int SaltLen = 32;
            const int NonceLen = 24;

            // dig params
            var encodedSpan = new ReadOnlySpan<byte>(
                Convert.FromBase64String(exportedAccount.encoded));
            var pos = SaltLen;
            var salt = encodedSpan[..pos].ToArray();
            var N = BitConverter.ToInt32(encodedSpan[pos..(pos + 4)]);
            pos += 4;
            var p = BitConverter.ToInt32(encodedSpan[pos..(pos + 4)]);
            pos += 4;
            var r = BitConverter.ToInt32(encodedSpan[pos..(pos + 4)]);
            if (N != DefaultN || p != DefaultP || r != DefaultR)
            {
                Debug.Fail("here means this is not exported from @polkadot{.js} extension.");
                return (false, new ImportedAccount());
            }

            // decrypt
            // maybe always single thread, as p is 1. always pass null here anyway. 
            var hashedPassPhrase = new ReadOnlySpan<byte>(SCrypt.ComputeDerivedKey(
                passPhrase, salt, DefaultN, DefaultR, DefaultP, null, DKLen));
            var cipherSet = encodedSpan[(SaltLen + 12)..];
            var nonce = cipherSet[..NonceLen];
            var cipher = cipherSet[NonceLen..];
            using var decrypter = new XSalsa20Poly1305(hashedPassPhrase);
            // header + private key (seed is smaller) + divider +  public key
            var bufferSize = 117;
            Span<byte> buffer = stackalloc byte[bufferSize];
            if (!decrypter.TryDecrypt(buffer, cipher, nonce))
            {
                Debug.Fail("here means (most likely) passphrase is wrong.");
                return (false, new ImportedAccount());
            }

            ReadOnlySpan<byte> keyHeader = stackalloc byte[]
            {
                48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32
            };
            ReadOnlySpan<byte> keyDivider = stackalloc byte[]
            {
                161, 35, 3, 33, 0
            };
            const int HeaderLen = 16;
            const int DividerLen = 5;
            const int PrivateKeyLen = 64;
            const int PublicKeyLen = 32;

            // verify
            pos = HeaderLen;
            var header = buffer[..pos];
            if (!header.SequenceEqual(keyHeader))
            {
                Debug.Fail("decrypted data is not a key.");
                return (false, new ImportedAccount());
            }

            var privateKey = buffer[pos..(pos + PrivateKeyLen)];
            pos += PrivateKeyLen;
            var divider = buffer[pos..(pos + DividerLen)];
            if (!divider.SequenceEqual(keyDivider))
            {
                // seed is stored. maybe old, no chance to happen.
                Debug.Fail("seed is found instead of key. re-export is needed.");
                return (false, new ImportedAccount());
            }

            pos += DividerLen;
            var publicKey = buffer[pos..(pos + PublicKeyLen)];

            // private key stored by @polkadot{.js} is actually conveted to ed25519 key.
            // https://github.com/polkadot-js/wasm/blob/master/packages/wasm-crypto/src/rs/sr25519.rs
            // need to re-convert to sr25519 key to sign...
            // but creating whole JIT conversion signature process as a library
            // like @polkadot{.js} is much better. 
            if (!TryFromEd25519PrivateKey(privateKey))
            {
                Debug.Fail("key conversion fail.");
                return (false, new ImportedAccount());
            }

            return (true, new ImportedAccount(exportedAccount.address, exportedAccount.meta,
                publicKey.ToArray(), privateKey.ToArray()));
        }

        // belowes are from schnorkel.
        // see https://github.com/w3f/schnorrkel

        static bool TryFromEd25519PrivateKey(Span<byte> privateKey)
        {
            if (privateKey.Length != 64)
            {
                return false;
            }

            var key = privateKey[..32];
            DivideScalarBytesByCofactor(key);
            return TryMakeScalar(key);
        }

        static void DivideScalarBytesByCofactor(Span<byte> scalar)
        {
            byte low = 0;
            for (int i = scalar.Length - 1; i >= 0 ; i--)
            {
                byte r = (byte)(scalar[i] & 0b0000_0111);
                scalar[i] >>= 3;
                scalar[i] += low;
                low = (byte)(r << 5);
            }
        }

        static bool TryMakeScalar(Span<byte> bytes)
        {
            if (bytes.Length != 32)
            {
                return false;
            }

            bytes[31] &= 0b0111_1111;
            return true;
        }
    }
}
