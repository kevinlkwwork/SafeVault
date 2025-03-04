namespace SafeVault.Helpers
{
    public static class ValidationHelper
    {
        public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
        {
            if (string.IsNullOrEmpty(input))
                return false;

            var validCharacters = allowedSpecialCharacters.ToHashSet();
            return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
        }

        public static bool IsValidXssInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return true;

            var disallowedPatterns = new[] { "<script", "<iframe", "javascript:", "<img", "onerror", "<svg" };

            foreach (var pattern in disallowedPatterns)
            {
                if (input.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            return true;
        }
    }
}