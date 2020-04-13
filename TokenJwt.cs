using BeetleX.FastHttpApi;
using Bumblebee;
using IdentityModel.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;

namespace Qbcode.IDS4
{
    internal class TokenJwt : ITokenValitator
    {
        private readonly Gateway gateway;
        private readonly JwksInfo jwks;

        private readonly string authority;

        private readonly JwtSecurityTokenHandler mJwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        private readonly IHttpClientFactory httpClientFactory;

        public TokenJwt(string authority, Gateway gateway)
        {
            this.gateway = gateway;
            this.authority = authority;

            var serviceProvider = new ServiceCollection().AddHttpClient().BuildServiceProvider();
            httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
            if (!string.IsNullOrWhiteSpace(authority))
            {
                jwks = GetJwks();
            }
        }

        private JwksInfo GetJwks()
        {
            JwksInfo result = new JwksInfo();

            if (!string.IsNullOrWhiteSpace(this.authority))
            {
                string jwksUrl = httpClientFactory.CreateClient().GetDiscoveryDocumentAsync(this.authority).Result.JwksUri;

                HttpResponseMessage resp = httpClientFactory.CreateClient().GetAsync(jwksUrl).Result;
                if (resp.IsSuccessStatusCode)
                {
                    result = JsonConvert.DeserializeObject<JwksInfo>(resp.Content.ReadAsStringAsync().Result);
                }
            }
            return result;
        }

        private JwtSecurityToken ValidateToken(string token)
        {
            return this.mJwtSecurityTokenHandler.ReadJwtToken(token);
        }

        public List<ClaimInfo> GetClaims(string jwt, SecretInfo secret)
        {
            bool isLog = gateway.HttpServer.EnableLog(BeetleX.EventArgs.LogType.Debug);
            List<ClaimInfo> result = new List<ClaimInfo>();

            if (!string.IsNullOrWhiteSpace(jwt))
            {
                JwtSecurityToken token = this.ValidateToken(jwt);
                if (token != null)
                {
                    if (!jwks.keys.Where(c => c.kid == token.Header.Kid).Any())
                    {
                        /* if (token.Issuer != this.authority)
                         {
                             if (isLog)
                             {
                                 gateway.HttpServer.Log(BeetleX.EventArgs.LogType.Error, $"issuer invalid\n Issuer:{token.Issuer} \n authority:{this.authority} ");
                             }
                         }
                         else*/
                        if (token.Payload.ValidTo.ToLocalTime() < DateTime.Now)
                        {
                            if (isLog)
                            {
                                gateway.HttpServer.Log(BeetleX.EventArgs.LogType.Error, "token is expired");
                                gateway.HttpServer.Log(BeetleX.EventArgs.LogType.Error, $"token time:{token.Payload.ValidTo.ToString("yyyy-MM-dd HH:mm:ss")} ");
                            }
                        }
                        else
                        {
                            result = token.Claims.Select(c => new ClaimInfo { Type = c.Type, Value = c.Value }).ToList();
                        }
                    }
                    else
                    {
                        if (isLog)
                        {
                            gateway.HttpServer.Log(BeetleX.EventArgs.LogType.Error, "kid not found in authority");
                        }
                    }
                }
            }
            else
            {
                if (isLog)
                {
                    gateway.HttpServer.Log(BeetleX.EventArgs.LogType.Error, "jwt token is empty");
                }
            }
            return result;
        }
    }

    class JwksInfo
    {
        public List<JwksItemInfo> keys { get; set; } = new List<JwksItemInfo>();
    }

    class JwksItemInfo
    {
        public string kty { get; set; } = string.Empty;
        public string use { get; set; } = string.Empty;
        public string kid { get; set; } = string.Empty;
        public string e { get; set; } = string.Empty;
        public string n { get; set; } = string.Empty;
        public string alg { get; set; } = string.Empty;
    }
}
