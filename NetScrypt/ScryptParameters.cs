namespace BlackFox.Cryptography.NetScrypt
{
    /// <summary>
    /// Store the scrypt tuning parameters, the size of the salt and the size of the resulting hashed value.
    /// </summary>
    public class ScryptParameters
    {
        /// <summary>CPU/memory cost parameter.  Must be a value 2^N.  2^14 (16384) causes a calculation time
        /// of approximately 50-70ms on 2010 era hardware; each successive value (eg. 2^15, 2^16, ...) should
        /// double the amount of CPU time and memory required.</summary>
        public ulong N { get; private set; }

        /// <summary>scrypt 'r' tuning parameter</summary>
        public uint R { get; private set; }

        /// <summary>scrypt 'p' tuning parameter (parallelization parameter); a large value of p can increase
        /// computational cost of scrypt without increasing the memory usage.</summary>
        public uint P { get; private set; }

        /// <summary>The number of bytes to store the password hash in.</summary>
        public uint HashLengthBytes { get; private set; }

        /// <summary>The number of bytes of random salt to generate.  The goal for the salt is
        /// to be unique.  16 bytes gives a 2^128 possible salt options, and roughly an N in 2^64 chance of a salt
        /// collision for N salts, which seems reasonable.  A larger salt requires more storage space, but doesn't
        /// affect the scrypt performance significantly.</summary>
        public uint SaltLengthBytes { get; private set; }

        /// <summary>
        /// Get an instance with some default values (N = 16384, r = 8, p = 1, 32 bytes hash, 16 bytes salt)
        /// </summary>
        public static ScryptParameters Default
        {
            get { return @default; }
        }

        static readonly ScryptParameters @default = new ScryptParameters(16384, 8, 1, 32, 16);

        public ScryptParameters(ulong n, uint r, uint p, uint hashLengthBytes, uint saltLengthBytes)
        {
            N = n;
            R = r;
            P = p;
            HashLengthBytes = hashLengthBytes;
            SaltLengthBytes = saltLengthBytes;
        }
    }
}