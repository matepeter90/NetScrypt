namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Runtime.CompilerServices;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using BlackFox.Cryptography.NetScrypt.Framework;

    class Program
    {
        /// <summary>
        /// Returns a Secure string from the source string
        /// </summary>
        /// <param name="Source"></param>
        /// <returns></returns>
        public static SecureString ToSecureString(string Source)
        {
            if (string.IsNullOrWhiteSpace(Source))
                return null;
            else
            {
                SecureString Result = new SecureString();
                foreach (char c in Source.ToCharArray())
                    Result.AppendChar(c);
                return Result;
            }
        }

        static void Main(string[] args)
        {
            var hash = NetScrypt.HashPassword("Hello world");
            Console.WriteLine(hash);
            Console.WriteLine(NetScrypt.Verify("Hello world", hash));
            Console.WriteLine(NetScrypt.Verify("Hello_world", hash));
            //Measure();

            long maxmem = 1024;
            double maxmemfrac = 0.125;
            TimeSpan maxtime = TimeSpan.FromSeconds(5);
            /*
            long n;
            int r;
            int p;
            ParameterSelection.PickParameters(maxmem, maxmemfrac, maxtime, out n, out r, out p);
            Console.WriteLine("N = {0} r = {1} p = {2}", n, r, p);
            */
            using(var input = new FileStream(@"E:\temp\HelloWorld.txt", FileMode.Open))
            using (var output = new FileStream(@"E:\temp\HelloWorld.txt.scrypt", FileMode.Create))
            {
                scryptenc_buf(input,
                    output,
                    ToSecureString("vbfox"), maxmem, maxmemfrac, maxtime);
            }

            //Console.WriteLine("salsa20/8 core per seconds: {0}", ComputeCoresPerSecond());
            Console.WriteLine("Done");
            Console.ReadLine();
        }

        static readonly byte[] scryptBytes = Encoding.ASCII.GetBytes("scrypt");

        static void scryptenc_setup(out byte[] header, out byte[] dk, SecureString password, long maxMemory, double maxMemoryPercentage,
            TimeSpan maxTime)
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

        static void scryptenc_buf(Stream inbuf, Stream outbuf, SecureString password, long maxMemory,
            double maxMemoryPercentage,
            TimeSpan maxTime)
        {
            /* Generate the header and derived key. */
            byte[] header, dk;
            scryptenc_setup(out header, out dk, password, maxMemory, maxMemoryPercentage, maxTime);

            /* Copy header into output buffer. */
            outbuf.Write(header, 0, header.Length);

            /* Encrypt data. */
            var aesCtr = new ScryptAesCtr(dk.Take(32).ToArray(), 0);
            aesCtr.EncryptOrDectrypt(inbuf, outbuf);

            /* Add signature. */
            var hmacKey = new byte[32];
            Array.Copy(dk, 32, hmacKey, 0, 32);
            var hmacSha256 = new HMACSHA256(hmacKey);
            outbuf.Position = 0;
            var headerHmac = hmacSha256.ComputeHash(outbuf);
            outbuf.Write(headerHmac, 0, 32);
        }

        static void Measure()
        {
            var bytes = Encoding.UTF8.GetBytes("Hello world");
            var salt = SaltWithParameters.GenerateSalt(new ScryptParameters(4096, 8, 1, 32, 16));

            Stopwatch watch = Stopwatch.StartNew();
            Parallel.For(0, 300, i => NetScrypt.DeriveKey(bytes, salt));
            watch.Stop();

            Console.WriteLine("Total = {0} ms, Average = {1} ms", watch.ElapsedMilliseconds,
                watch.ElapsedMilliseconds/100);
        }
    }

    class ScryptAesCtr
    {
        readonly long nonce;
        long byteCounter;
        readonly byte[] buf = new byte[16];

        private readonly Aes aes;

        public ScryptAesCtr(byte[] key, long nonce)
        {
            var iv = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                iv[i] = 0;
            }

            aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            this.nonce = nonce;
        }

        public void EncryptOrDectrypt(Stream input, Stream output)
        {
	        var pblk = new byte[16];

            ICryptoTransform aesEncryptor = aes.CreateEncryptor();
            byte[] nonceArray = BitConverter.GetBytes(nonce);
            if (BitConverter.IsLittleEndian) Array.Reverse(nonceArray);

            for (long pos = 0; pos < input.Length; pos++)
            {
		        /* How far through the buffer are we? */
                int bytemod = (int)(byteCounter % 16);

		        /* Generate a block of cipherstream if needed. */
		        if (bytemod == 0)
		        {
		            Array.Copy(nonceArray, 0, pblk, 0, nonceArray.Length);
		            var counterBytes = BitConverter.GetBytes(byteCounter / 16);
		            if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);
                    Array.Copy(counterBytes, 0, pblk, 8, counterBytes.Length);
		            aesEncryptor.TransformBlock(pblk, 0, pblk.Length, buf, 0);
		        }

		        /* Encrypt a byte. */
                var newbyte = input.ReadByte() ^ buf[bytemod];
                output.WriteByte((byte)newbyte);

		        /* Move to the next byte of cipherstream. */
                byteCounter += 1;
	        }
        }
    }
}
