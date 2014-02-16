namespace BlackFox.Cryptography.NetScrypt
{
    using System.Security.Cryptography;

    public static class SaltGenerator
    {
        private static readonly RNGCryptoServiceProvider rngCryptoProvider = new RNGCryptoServiceProvider();

        public static byte[] GenerateRandomSalt(uint bytes)
        {
            var result = new byte[bytes];
            rngCryptoProvider.GetBytes(result);
            return result;
        }
    }
}