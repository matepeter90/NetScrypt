namespace BlackFox.Cryptography.NetScrypt.Framework
{
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security;

    internal static class LibScrypt
    {
        static readonly IScryptDllImport dllImport;
        static LibScrypt()
        {
            switch (IntPtr.Size)
            {
                case 4:
                    dllImport = new ScryptDllImportWin32();
                    break;

                case 8:
                    dllImport = new ScryptDllImportX64();
                    break;

                default:
                    throw new InvalidOperationException("Not supported platform");
            }
        }

        private static unsafe byte[] Scrypt(IntPtr password, int passwordLength, byte[] salt, ulong n, uint r, uint p,
            uint derivedKeyLengthBytes)
        {
            var saltLength = salt.Length;
            if (saltLength == 0) salt = pseudoEmptyBytes;

            var derivedKey = (derivedKeyLengthBytes == 0) ? pseudoEmptyBytes : new byte[derivedKeyLengthBytes];

            fixed (byte* saltPtr = &salt[0])
            fixed (byte* derivedKeyPtr = &derivedKey[0])
            {
                var scryptResult = dllImport.Scrypt(password, new UIntPtr((uint)passwordLength),
                    new IntPtr(saltPtr), new UIntPtr((uint)saltLength),
                    n, r, p,
                    new IntPtr(derivedKeyPtr), new UIntPtr(derivedKeyLengthBytes));

                if (scryptResult != 0)
                {
                    throw new ScryptInternalErrorException();
                }
            }

            return (derivedKeyLengthBytes == 0) ? new byte[0] : derivedKey;
        }

        static readonly byte[] pseudoEmptyBytes = { 0 };

        public unsafe static byte[] Scrypt(byte[] password, byte[] salt, ulong n, uint r, uint p,
            uint derivedKeyLengthBytes)
        {
            var passwordLength = password.Length;
            if (passwordLength == 0) password = pseudoEmptyBytes;

            fixed (byte* passwordPtr = &password[0])
            {
                return Scrypt(new IntPtr(passwordPtr), passwordLength, salt, n, r, p, derivedKeyLengthBytes);
            }
        }

        public static byte[] Scrypt(SecureString password, byte[] salt, ulong n, uint r, uint p,
            uint derivedKeyLengthBytes)
        {
            var passwordPtr = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                passwordPtr = Marshal.SecureStringToGlobalAllocUnicode(password);
                return Scrypt(passwordPtr, password.Length, salt, n, r, p, derivedKeyLengthBytes);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(passwordPtr);
            }
        }
    }
}