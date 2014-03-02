namespace BlackFox.Cryptography.Scrypt
{
    using System;

    class UnrecognizedFormatVersionException : Exception
    {
        public UnrecognizedFormatVersionException()
            : base("Unrecognized scrypt format version")
        {
        }
    }
}