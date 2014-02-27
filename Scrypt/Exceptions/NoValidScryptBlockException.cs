﻿namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;

    class NoValidScryptBlockException : Exception
    {
        public NoValidScryptBlockException(string reason)
            : base("Input is not valid scrypt-encrypted block: " + reason)
        {
        }
    }
}
