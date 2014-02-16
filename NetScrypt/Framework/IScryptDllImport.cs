namespace BlackFox.Cryptography.NetScrypt.Framework
{
    using System;

    internal interface IScryptDllImport
    {
        int Scrypt(IntPtr passwd, UIntPtr passwdlen, IntPtr salt, UIntPtr saltlen, ulong n, uint r, uint p, IntPtr buf,
            UIntPtr buflen);
    }
}