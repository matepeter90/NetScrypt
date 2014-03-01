namespace BlackFox.Cryptography.NetScrypt.Framework
{
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security;

    public static class LibScrypt
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

        private static unsafe void Scrypt(IntPtr password, int passwordLength, byte[] salt, ulong n, uint r, uint p,
            byte[] derivedKey)
        {
            var saltLength = salt != null ? salt.Length : 0;
            var saltNotNullOrEmpty = salt == null || saltLength == 0 ? pseudoEmptyBytes : salt;

            // Simplify the code by always pinning the array
            var derivedKeyForPinning = derivedKey ?? pseudoEmptyBytes;

            fixed (byte* saltPtr = &saltNotNullOrEmpty[0])
            fixed (byte* derivedKeyPtr = &derivedKeyForPinning[0])
            {
                var scryptResult = dllImport.Scrypt(
                    password,
                    new UIntPtr((uint)passwordLength),
                    saltLength > 0 ? new IntPtr(saltPtr) : IntPtr.Zero,
                    new UIntPtr((uint)saltLength),
                    n,
                    r,
                    p,
                    derivedKey != null ? new IntPtr(derivedKeyPtr) : IntPtr.Zero,
                    derivedKey != null ? new UIntPtr((uint)derivedKey.Length) : UIntPtr.Zero);

                if (scryptResult != 0)
                {
                    throw new ScryptInternalErrorException();
                }
            }
        }

        static readonly byte[] pseudoEmptyBytes = { 0 };

        public unsafe static void Scrypt(byte[] password, byte[] salt, ulong n, uint r, uint p,
            byte[] derivedKey)
        {
            var passwordLength = password != null ? password.Length : 0;
            var passwordNotNullOrEmpty = password == null || passwordLength == 0 ? pseudoEmptyBytes : password;

            fixed (byte* passwordPtr = &passwordNotNullOrEmpty[0])
            {
                Scrypt(
                    passwordLength > 0 ? new IntPtr(passwordPtr) : IntPtr.Zero,
                    passwordLength,
                    salt,
                    n,
                    r,
                    p,
                    derivedKey);
            }
        }

        public static void ScryptUnicode(SecureString password, byte[] salt, ulong n, uint r, uint p,
            byte[] derivedKey)
        {
            var passwordPtr = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                passwordPtr = Marshal.SecureStringToGlobalAllocUnicode(password);
                Scrypt(passwordPtr, password.Length, salt, n, r, p, derivedKey);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(passwordPtr);
            }
        }

        public static void ScryptAnsi(SecureString password, byte[] salt, ulong n, uint r, uint p,
            byte[] derivedKey)
        {
            var passwordPtr = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                passwordPtr = Marshal.SecureStringToGlobalAllocAnsi(password);
                Scrypt(passwordPtr, password.Length, salt, n, r, p, derivedKey);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocAnsi(passwordPtr);
            }
        }
    }
}