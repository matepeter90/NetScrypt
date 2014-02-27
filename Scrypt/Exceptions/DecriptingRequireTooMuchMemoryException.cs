namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;

    class DecriptingRequireTooMuchMemoryException : Exception
    {
        public DecriptingRequireTooMuchMemoryException()
            : base("Decrypting file would require too much memory")
        {
        }
    }
}