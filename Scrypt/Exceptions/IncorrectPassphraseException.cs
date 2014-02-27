namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;

    class IncorrectPassphraseException : Exception
    {
        public IncorrectPassphraseException()
            : base("Passphrase is incorrect")
        {
        }
    }
}