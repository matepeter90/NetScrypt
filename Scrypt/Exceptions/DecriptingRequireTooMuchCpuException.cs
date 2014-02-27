namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;

    class DecriptingRequireTooMuchCpuException : Exception
    {
        public DecriptingRequireTooMuchCpuException()
            : base("Decrypting file would take too much CPU time")
        {

        }
    }
}