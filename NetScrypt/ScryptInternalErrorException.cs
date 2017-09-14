namespace BlackFox.Cryptography.NetScrypt
{
    using System;
    using System.Runtime.Serialization;

    [Serializable]
    public class ScryptInternalErrorException : Exception
    {
        public ScryptInternalErrorException()
            : base("Internal error in crypto_scrypt")
        {
        }
    }
}