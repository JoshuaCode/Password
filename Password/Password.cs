using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JoshuaCode.Cryptography
{
    public class Password
    {
        public static string GeneratePassword(int keyLength, PasswordPolicy passwordPolicy)
        {
            if(keyLength < passwordPolicy.MinimumLength || keyLength > passwordPolicy.MaximumLength)
            {
                throw new ArgumentOutOfRangeException($"{nameof(keyLength)} did not meet {nameof(passwordPolicy)}");
            }
            return GeneratePassword(keyLength, passwordPolicy.CharacterSets);
        }

        public static string GeneratePassword(int keyLength, IEnumerable<CharacterSet> characterSets)
        {
            StringBuilder requiredKey = new StringBuilder(keyLength);
            //Default StringBuilder capacity is 16. Setting to 64 to reduce reallocates and copies of the data. 
            //This is assuming that the character sets will include upper and lower case letters along with 
            //numbers the majority of the time.
            StringBuilder joinedCharacterSets = new StringBuilder(64);

            foreach (CharacterSet characterSet in characterSets)
            {
                joinedCharacterSets.Append(characterSet.AllowedCharacters);
                if (characterSet.MinimumNumberRequired > 0)
                {
                    requiredKey.Append(GeneratePassword(characterSet.MinimumNumberRequired, characterSet.AllowedCharacters));
                }
            }
            int remainingKeyLength = keyLength - requiredKey.Length;
            if (remainingKeyLength > 0)
            {
                //Performing char[] to char[] copy. Could use joinedCharacterSets.ToString().ToCharArray() but you are creating an unnecessary string allocation. 
                char[] joinedCharacters = new char[joinedCharacterSets.Length];
                joinedCharacterSets.CopyTo(0, joinedCharacters, 0, joinedCharacterSets.Length);

                requiredKey.Append(GeneratePassword(remainingKeyLength, joinedCharacters));
            }
            //Performing char[] to char[] copy. Could use requiredKey.ToString().ToCharArray() but you are creating an unnecessary string allocation. 
            char[] password = new char[requiredKey.Length];
            requiredKey.CopyTo(0, password, 0, requiredKey.Length);

            //Shuffle password so characters from character sets don't always appear in the same position.
            Shuffle(password);

            return new string(password);
        }

        public static char[] GeneratePassword(int keyLength, char[] allowedCharacterSet)
        {
            byte[] data = new byte[1];
            //Using System.Security.Cryptography.RNGCryptoServiceProvider class instead of the System.Random to ensure crytographic strength
            using (RandomNumberGenerator crypto = RandomNumberGenerator.Create())
            {
                crypto.GetBytes(data);
                data = new byte[keyLength];
                crypto.GetBytes(data);
            }
            char[] result = new char[keyLength];
            for (int index = 0; index < data.Length; index++)
            {
                result[index] = (allowedCharacterSet[data[index] % (allowedCharacterSet.Length)]);
            }
            return result;
        }

        private static void Shuffle<T>(T[] array)
        {
            byte[] data = new byte[1];
            //Using System.Security.Cryptography.RNGCryptoServiceProvider class instead of the System.Random to ensure crytographic strength
            using (RandomNumberGenerator crypto = RandomNumberGenerator.Create())
            {
                crypto.GetBytes(data);
                data = new byte[array.Length];
                crypto.GetBytes(data);
            }
            for (int index = 0; index < data.Length; index++)
            {
                int newIndex = data[index] % (array.Length);
                T t = array[newIndex];
                array[newIndex] = array[index];
                array[index] = t;
            }
        }
    }
}
