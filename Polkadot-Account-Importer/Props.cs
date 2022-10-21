using System;

namespace PolkadotAccountImporter
{
    public class ImportedAccount
    {
        readonly string address;
        readonly AccountMetadata meta;
        readonly byte[] publicKey;
        readonly byte[] privateKey;

        public string GetAddress => address;

        public AccountMetadata GetMetadata => meta;

        public byte[] GetPublicKey
            => publicKey;

        public byte[] GetPrivateKey => privateKey;

        public ImportedAccount(string address, AccountMetadata meta, 
            byte[] publicKey, byte[] privateKey)
        {
            this.address = address;
            this.meta = meta;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public ImportedAccount()
        {
            address = string.Empty;
            meta = new AccountMetadata();
            publicKey = Array.Empty<byte>();
            privateKey = Array.Empty<byte>();
        }
    }

    public class ExportedAccountFormat
    {
        public readonly string encoded;
        public readonly AccountEncoding encoding;
        public readonly string address;
        public readonly AccountMetadata meta;

        public ExportedAccountFormat(string encoded, AccountEncoding encoding, 
            string address, AccountMetadata meta)
        {
            this.encoded = encoded;
            this.encoding = encoding;
            this.address = address;
            this.meta = meta;
        }
    }

    public class AccountEncoding
    {
        public readonly string[] content;
        public readonly string[] type;
        public readonly string version;

        public AccountEncoding(string[] content, string[] type, string version)
        {
            this.content = content;
            this.type = type;
            this.version = version;
        }
    }

    public class AccountMetadata
    {
        public readonly string genesisHash;
        public readonly bool isHidden;
        public readonly string name;
        public readonly ulong whenCreated;

        public AccountMetadata(string genesisHash, bool isHidden, string name, ulong whenCreated)
        {
            this.genesisHash = genesisHash;
            this.isHidden = isHidden;
            this.name = name;
            this.whenCreated = whenCreated;
        }

        public AccountMetadata()
        {
            genesisHash = string.Empty;
            name = string.Empty;
        }
    }
}