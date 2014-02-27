namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;

    class DecryptingRequireTooMuchMemoryException : Exception
    {
        public DecryptingRequireTooMuchMemoryException()
            : base("Decrypting file would require too much memory")
        {
        }
    }
}