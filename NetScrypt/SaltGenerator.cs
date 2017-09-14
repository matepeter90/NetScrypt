namespace BlackFox.Cryptography.NetScrypt
{
    using System;
    using System.Security.Cryptography;

    public static class SaltGenerator
    {
        [ThreadStatic]
        private static RandomNumberGenerator rng;

        public static byte[] GenerateRandomSalt(uint bytes)
        {
            if (rng == null)
            {
                rng = RandomNumberGenerator.Create();
            }

            var result = new byte[bytes];
            rng.GetBytes(result);
            return result;
        }
    }
}