namespace BlackFox.Cryptography.Scrypt
{
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security;

    static class SecureStringUtils
    {
        /// <summary>
        /// Compare two <see cref="SecureString"/> instances for equality.
        /// <para>A timing attack would leak <code>max(len(a), len(b)).</code></para>
        /// </summary>
        public static bool Equals(SecureString a, SecureString b)
        {
            if (a == null)
            {
                throw new ArgumentNullException("a");
            }
            if (b == null)
            {
                throw new ArgumentNullException("b");
            }

            var bstrA = IntPtr.Zero;
            var bstrB = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();

            try
            {
                bstrA = Marshal.SecureStringToBSTR(a);
                bstrB = Marshal.SecureStringToBSTR(b);

                var lengthA = a.Length;
                var lengthB = b.Length;
                var diff = lengthA ^ lengthB;
                var count = Math.Max(lengthA, lengthB);

                unsafe
                {
                    var pA = (char*)bstrA.ToPointer();
                    var pB = (char*)bstrB.ToPointer();

                    for (var i = 0; i < count; i++)
                    {
                        diff |= pA[i % (lengthA + 1)] ^ pB[i % (lengthB + 1)];
                    }
                }

                return diff == 0;
            }
            finally
            {
                if (bstrA != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstrA);
                }

                if (bstrB != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstrB);
                }
            }
        } 
    }
}