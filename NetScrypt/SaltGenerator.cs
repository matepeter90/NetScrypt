namespace BlackFox.Cryptography.NetScrypt
{
    using System;
    using System.Security.Cryptography;

    public static class SaltGenerator
    {
        [ThreadStatic]
        private static RNGCryptoServiceProvider rngCryptoProvider;

        public static byte[] GenerateRandomSalt(uint bytes)
        {
            if (rngCryptoProvider == null)
            {
                rngCryptoProvider = new RNGCryptoServiceProvider();
            }

            var result = new byte[bytes];
            rngCryptoProvider.GetBytes(result);
            return result;
        }
    }
}