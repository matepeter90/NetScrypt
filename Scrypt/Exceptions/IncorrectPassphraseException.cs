namespace BlackFox.Cryptography.Scrypt
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