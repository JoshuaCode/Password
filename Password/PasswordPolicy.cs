using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JoshuaCode.Cryptography
{
    public class PasswordPolicy
    {
        public int MinimumLength { get; }
        public int MaximumLength { get; }
        public IEnumerable<CharacterSet> CharacterSets { get; set; }

        public PasswordPolicy(IEnumerable<CharacterSet> characterSets, int minimumLength = 8, int maximumLength = 64)
        {
            if (minimumLength < 0)
            {
                throw new ArgumentOutOfRangeException($"{nameof(minimumLength)} must be greater than zero.");
            }
            if (maximumLength < 0)
            {
                throw new ArgumentOutOfRangeException($"{nameof(maximumLength)} must be greater than zero.");
            }
            if (characterSets?.Count() == 0)
            {
                throw new ArgumentOutOfRangeException($"{nameof(characterSets)} must contain one or more CharacterSet.");
            }
            CharacterSets = characterSets;
            MinimumLength = minimumLength;
            MaximumLength = maximumLength;
        }

        public static bool IsPasswordCompliantWithPasswordPolicy(string password, PasswordPolicy passwordPolicy)
        {
            if(password.Length < passwordPolicy.MinimumLength || password.Length > passwordPolicy.MaximumLength)
            {
                return false;
            }
            foreach(CharacterSet characterSet in passwordPolicy.CharacterSets)
            {
                int characterCount = 0;
                int index = 0;
                while(index >= 0)
                {
                    index = password.IndexOfAny(characterSet.AllowedCharacters, index);
                    if(index >= 0)
                    {
                        characterCount++;
                    }
                    if(characterCount >= characterSet.MinimumNumberRequired)
                    {
                        break;
                    }
                }
                if(characterCount < characterSet.MinimumNumberRequired)
                {
                    return false;
                }
            }
            return true;
        }

        public static string GeneratePasswordPolicyDescription(PasswordPolicy passwordPolicy)
        {
            StringBuilder passwordPolicyDescription = new StringBuilder();
            passwordPolicyDescription.AppendLine("Password must meet the following guidelines:");
            passwordPolicyDescription.AppendLine($"  * The password must be between {passwordPolicy.MinimumLength} and {passwordPolicy.MaximumLength} characters long.");
            passwordPolicyDescription.AppendLine($"  * The password contains characters from the following categories:");
            foreach (CharacterSet characterSet in passwordPolicy.CharacterSets)
            {
                passwordPolicyDescription.AppendLine($"    - At least {characterSet.MinimumNumberRequired} of the following characters ({new string(characterSet.AllowedCharacters)})");
            }
            return passwordPolicyDescription.ToString();
        }
    }
}
