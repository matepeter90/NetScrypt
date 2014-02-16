namespace BlackFox.Cryptography.NetScrypt
{
    using System;
    using System.Security;
    using System.Text;
    using BlackFox.Cryptography.NetScrypt.Framework;

    public static class NetScrypt
    {
        public static string HashPassword(string password)
        {
            return HashPassword(password, SaltWithParameters.GenerateSalt(), Encoding.Unicode);
        }

        public static string HashPassword(string password, SaltWithParameters saltWithParameters)
        {
            return HashPassword(password, saltWithParameters, Encoding.Unicode);
        }

        public static string HashPasswordUtf8(string password)
        {
            return HashPassword(password, SaltWithParameters.GenerateSalt(), Encoding.UTF8);
        }

        public static string HashPasswordUtf8(string password, SaltWithParameters saltWithParameters)
        {
            return HashPassword(password, saltWithParameters, Encoding.UTF8);
        }

        private static string HashPassword(string password, SaltWithParameters saltWithParameters, Encoding passwordEncoding)
        {
            var hashBytes = DeriveKey(passwordEncoding.GetBytes(password), saltWithParameters);
            var hashString = Convert.ToBase64String(hashBytes);
            return HashedPasswordString.Create(saltWithParameters, hashString);
        }

        public static string HashPassword(SecureString password)
        {
            return HashPassword(password, SaltWithParameters.GenerateSalt());
        }

        public static string HashPassword(SecureString password, SaltWithParameters saltWithParameters)
        {
            var hashBytes = DeriveKey(password, saltWithParameters);
            var hashString = Convert.ToBase64String(hashBytes);
            return HashedPasswordString.Create(saltWithParameters, hashString);
        }

        public static bool Verify(SecureString password, string hash)
        {
            string _;
            SaltWithParameters saltWithParameters;
            HashedPasswordString.Parse(hash, out saltWithParameters, out _);

            return hash == HashPassword(password, saltWithParameters);
        }

        public static bool Verify(string password, string hash)
        {
            string _;
            SaltWithParameters saltWithParameters;
            HashedPasswordString.Parse(hash, out saltWithParameters, out _);

            return hash == HashPassword(password, saltWithParameters);
        }

        /// <summary>The 'raw' scrypt key-derivation function.</summary>
        /// <param name="password">The password bytes to generate the key based upon.</param>
        /// <param name="saltWithParameters">The salt and parameters to use for the generation.</param>
        /// <remarks>The encoding used is the system Unicode encoding (UTF-16)</remarks>
        public static byte[] DeriveKey(SecureString password, SaltWithParameters saltWithParameters)
        {
            return LibScrypt.ScryptUnicode(password, saltWithParameters.Salt, saltWithParameters.Parameters.N,
                saltWithParameters.Parameters.R, saltWithParameters.Parameters.P,
                saltWithParameters.Parameters.HashLengthBytes);
        }

        /// <summary>The 'raw' scrypt key-derivation function.</summary>
        /// <param name="password">The password bytes to generate the key based upon.</param>
        /// <param name="saltWithParameters">The salt and parameters to use for the generation.</param>
        public static byte[] DeriveKey(byte[] password, SaltWithParameters saltWithParameters)
        {
            return LibScrypt.Scrypt(password, saltWithParameters.Salt, saltWithParameters.Parameters.N,
                saltWithParameters.Parameters.R, saltWithParameters.Parameters.P,
                saltWithParameters.Parameters.HashLengthBytes);
        }
    }
}