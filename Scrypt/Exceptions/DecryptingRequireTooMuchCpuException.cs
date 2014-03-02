namespace BlackFox.Cryptography.Scrypt
{
    using System;

    class DecryptingRequireTooMuchCpuException : Exception
    {
        public DecryptingRequireTooMuchCpuException()
            : base("Decrypting file would take too much CPU time")
        {

        }
    }
}