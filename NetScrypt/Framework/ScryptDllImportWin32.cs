namespace BlackFox.Cryptography.NetScrypt.Framework
{
    using System;
    using System.Runtime.InteropServices;

    internal class ScryptDllImportWin32 : IScryptDllImport
    {
        [DllImport("libscrypt-win32.dll", EntryPoint = "crypto_scrypt")]
        private static extern int Scrypt(IntPtr passwd, UIntPtr passwdlen, IntPtr salt, UIntPtr saltlen, ulong n,
            uint r, uint p, IntPtr buf, UIntPtr buflen);

        int IScryptDllImport.Scrypt(IntPtr passwd, UIntPtr passwdlen, IntPtr salt, UIntPtr saltlen, ulong n, uint r, uint p, IntPtr buf,
            UIntPtr buflen)
        {
            return Scrypt(passwd, passwdlen, salt, saltlen, n, r, p, buf, buflen);
        }
    }
}