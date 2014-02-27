namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;
    using System.Diagnostics;
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

            var rBytes = GetBigEndianBytesFromInt32(r);
            Array.Copy(rBytes, 0, header, 8, rBytes.Length);

            var pBytes = GetBigEndianBytesFromInt32(p);
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

        static byte[] GetBigEndianBytesFromInt32(int value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
            return bytes;
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

        public void ParseAndCheckHeader(byte[] header, out byte[] dk)
        {
            /* Parse N, r, p, salt. */
            var logN = (int)header[7];
            var r = GetIn32FromBigEndianBytes(header, 8);
            var p = GetIn32FromBigEndianBytes(header, 12);
            
            var salt = new byte[32];
            Array.Copy(header, 16, salt, 0, 32);

            /* Verify header checksum. */
            var sha256 = SHA256.Create();
            var headerHash = sha256.ComputeHash(header, 0, 48);
            var computedChecksum = headerHash.Take(16).ToArray();
            var checksumInFile = header.Skip(48).Take(16).ToArray();
            if (!checksumInFile.SequenceEqual(computedChecksum))
            {
                throw new NoValidScryptBlockException("Header checksum failed");
            }

            /*
             * Check whether the provided parameters are valid and whether the
             * key derivation function can be computed within the allowed memory
             * and CPU time.
             */
            ParameterSelection.CheckParameters(maxMemory, maxMemoryPercentage, maxTime.TotalSeconds, logN, r, p);

            /* Compute the derived keys. */
            var n = (long)(1) << logN;
            dk = LibScrypt.ScryptAnsi(password, salt, (ulong)n, (uint)r, (uint)p, 64);

            /* Check header signature (i.e., verify password). */
            var hmacKey = new byte[32];
            Array.Copy(dk, 32, hmacKey, 0, 32);
            var hmacSha256 = new HMACSHA256(hmacKey);
            var computedHmac = hmacSha256.ComputeHash(header, 0, 64).Take(32);
            var hmacInFile = header.Skip(64).Take(32);
            if (!hmacInFile.SequenceEqual(computedHmac))
            {
                throw new IncorrectPassphraseException();
            }

            /* Success! */
        }

        static int GetIn32FromBigEndianBytes(byte[] buffer, int start)
        {
            if (BitConverter.IsLittleEndian)
            {
                var bytes = new byte[4];
                Array.Copy(buffer, start, bytes, 0, 4);
                Array.Reverse(bytes);
                return BitConverter.ToInt32(bytes, 0);
            }

            return BitConverter.ToInt32(buffer, start);
        }

        public void Decrypt(Stream input, Stream output)
        {
            if (input == null) throw new ArgumentNullException("input");
            if (output == null) throw new ArgumentNullException("output");

            /*
             * All versions of the scrypt format will start with "scrypt" and
             * have at least 7 bytes of header.
             */
            if (input.Length < 7)
            {
                throw new NoValidScryptBlockException("File really too small");
            }

            var header = new byte[96];
            input.Read(header, 0, header.Length); // TODO: Check result & loop

            var marker = header.Take(scryptBytes.Length).ToArray();
            if (!marker.SequenceEqual(scryptBytes))
            {
                throw new NoValidScryptBlockException("No file marker");
            }

            /* Check the format. */
            if (header[6] != 0)
            {
                throw new UnrecognizedFormatVersionException();
            }

            /* We must have at least 128 bytes. */
            if (input.Length < 128)
            {
                throw new NoValidScryptBlockException("File too small");
            }

            /* Parse the header and generate derived keys. */
            byte[] dk;
            ParseAndCheckHeader(header, out dk);

            /* Decrypt data. */
            using (var aesCtr = new ScryptAesCtr(dk.Take(32).ToArray(), 0))
            {
                aesCtr.EncryptOrDectrypt(input, output);
            }

            /* Verify signature. */
            var hmacKey = new byte[32];
            Array.Copy(dk, 32, hmacKey, 0, 32);
            var hmacSha256 = new HMACSHA256(hmacKey);
            input.Position = 0;
            var inputArray = StreamToArray(input); // TODO: Create a virtual stream over the input
            var computedHmac = hmacSha256.ComputeHash(inputArray, 0, inputArray.Length - 32);
            input.Position = input.Length - 32;
            var hmacInFile = new byte[32];
            input.Read(hmacInFile, 0, 32);// TODO: Check result & loop
            if (!hmacInFile.SequenceEqual(computedHmac))
            {
                throw new NoValidScryptBlockException("Signature don't verify");
            }

            /* Zero sensitive data. */
            //TODO: Pretty useless without pinning the array in the first place
            for (int i = 0; i < dk.Length; i++)
            {
                dk[i] = 0;
            }

            /* Success! */
        }

        public static byte[] StreamToArray(Stream input)
        {
            var buffer = new byte[16 * 1024];
            using (var ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
    }
}