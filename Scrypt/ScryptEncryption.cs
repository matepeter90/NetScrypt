namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;
    using BlackFox.Cryptography.NetScrypt.Framework;

    class ScryptEncryption
    {
        readonly SecureString password;
        readonly long maxMemory;
        readonly double maxMemoryPercentage;
        readonly TimeSpan maxTime;

        public ScryptEncryption(SecureString password, long maxMemory, double maxMemoryPercentage, TimeSpan maxTime)
        {
            if (password == null) throw new ArgumentNullException("password");

            this.password = password;
            this.maxMemory = maxMemory;
            this.maxMemoryPercentage = maxMemoryPercentage;
            this.maxTime = maxTime;
        }

        static readonly byte[] scryptBytes = Encoding.ASCII.GetBytes("scrypt");

        private void CreateHeader(out byte[] header, out byte[] dk)
        {
            /* Pick values for N, r, p. */
            int r, p, logN;
            ParameterSelection.PickParametersCore(maxMemory, maxMemoryPercentage, maxTime.TotalSeconds, out logN, out r, out p);
            long n = 1L << logN;

            /* Get some salt. */
            var salt = SaltGenerator.GenerateRandomSalt(32);

            /* Generate the derived keys. */
            dk = LibScrypt.ScryptAnsi(password, salt, (ulong)n, (uint)r, (uint)p, 64);

            /* Construct the file header. */
            header = new byte[96];
            Array.Copy(scryptBytes, header, scryptBytes.Length);
            header[6] = 0;
            header[7] = (byte)logN;

            var rBytes = BitConverter.GetBytes(r);
            if (BitConverter.IsLittleEndian) Array.Reverse(rBytes);
            Array.Copy(rBytes, 0, header, 8, rBytes.Length);

            var pBytes = BitConverter.GetBytes(p);
            if (BitConverter.IsLittleEndian) Array.Reverse(pBytes);
            Array.Copy(pBytes, 0, header, 12, pBytes.Length);
            Array.Copy(salt, 0, header, 16, salt.Length);

            /* Add header checksum. */
            var sha256 = SHA256.Create();
            var headerHash = sha256.ComputeHash(header, 0, 48);
            Array.Copy(headerHash, 0, header, 48, 16);

            /* Add header signature (used for verifying password). */
            var hmacKey = new byte[32];
            Array.Copy(dk, 32, hmacKey, 0, 32);
            var hmacSha256 = new HMACSHA256(hmacKey);
            var headerHmac = hmacSha256.ComputeHash(header, 0, 64);
            Array.Copy(headerHmac, 0, header, 64, 32);
        }

        public void Encrypt(Stream input, Stream output)
        {
            if (input == null) throw new ArgumentNullException("input");
            if (output == null) throw new ArgumentNullException("output");

            /* Generate the header and derived key. */
            byte[] header, dk;
            CreateHeader(out header, out dk);

            /* Copy header into output buffer. */
            output.Write(header, 0, header.Length);

            /* Encrypt data. */
            var aesCtr = new ScryptAesCtr(dk.Take(32).ToArray(), 0);
            aesCtr.EncryptOrDectrypt(input, output);

            /* Add signature. */
            var hmacKey = new byte[32];
            Array.Copy(dk, 32, hmacKey, 0, 32);
            var hmacSha256 = new HMACSHA256(hmacKey);
            output.Position = 0;
            var headerHmac = hmacSha256.ComputeHash(output);
            output.Write(headerHmac, 0, 32);
        }
    }
}