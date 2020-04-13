using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Qbcode.IDS4
{
    internal interface ITokenValitator
    {
        List<ClaimInfo> GetClaims(string token, SecretInfo secret);
    }

    internal class ClaimInfo
    {
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
    }

    internal class SecretInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Secret { get; set; } = string.Empty;

        public SecretInfo() { }

        public SecretInfo(string id, string secret)
        {
            Id = id;
            Secret = secret;
        }
    }
}
