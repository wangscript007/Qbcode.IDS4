using BeetleX.EventArgs;
using Bumblebee;
using IdentityModel.Client;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;

namespace Qbcode.IDS4
{
    internal class TokenReference : ITokenValitator
    {
        private readonly Gateway gateway;
        private readonly string endpoint = string.Empty;
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IDistributedCache cache;
        private readonly int cacheDuration = 0;


        public TokenReference(string authority, int cacheDuration, Gateway gateway)
        {
            this.gateway = gateway;

            this.cacheDuration = cacheDuration;

            var serviceCollection = new ServiceCollection();

            serviceCollection.AddHttpClient();
            serviceCollection.AddDistributedMemoryCache();

            var serviceProvider = serviceCollection.BuildServiceProvider();

            cache = serviceProvider.GetService<IDistributedCache>();

            httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();

            if (!string.IsNullOrWhiteSpace(authority))
            {
                endpoint = httpClientFactory.CreateClient().GetDiscoveryDocumentAsync(authority).Result.IntrospectionEndpoint;
            }
        }

        public List<ClaimInfo> GetClaims(string token, SecretInfo secret)
        {
            List<ClaimInfo> result = new List<ClaimInfo>();

            if (gateway.HttpServer.EnableLog(LogType.Debug))
            {
                gateway.HttpServer.Log(LogType.Debug, $"secret:{JsonConvert.SerializeObject(secret)}");
            }

            if (cacheDuration <= 0)
            {
                if (gateway.HttpServer.EnableLog(LogType.Debug))
                {
                    gateway.HttpServer.Log(LogType.Debug, "not set cacheDuration, get in url");
                }
                result = _GetClaims(token, secret);
            }
            else
            {
                string cacheStr = cache.GetString(token);
                if (!string.IsNullOrWhiteSpace(cacheStr))
                {
                    if (gateway.HttpServer.EnableLog(LogType.Debug))
                    {
                        gateway.HttpServer.Log(LogType.Debug, "found claims in  cache :" + cacheStr);
                    }

                    result = JsonConvert.DeserializeObject<List<ClaimInfo>>(cacheStr);
                }
                else
                {
                    if (gateway.HttpServer.EnableLog(LogType.Debug))
                    {
                        gateway.HttpServer.Log(LogType.Warring, "not found claims in  cache ");
                    }

                    result = _GetClaims(token, secret);

                    if (result.Any())
                    {
                        cache.SetString(token, JsonConvert.SerializeObject(result), new DistributedCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(cacheDuration)
                        });
                    }
                    else
                    {
                        cache.SetString(token, JsonConvert.SerializeObject(result), new DistributedCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(60)
                        });
                    }
                }
            }

            return result;
        }

        private List<ClaimInfo> _GetClaims(string token, SecretInfo secret)
        {
            if (!string.IsNullOrWhiteSpace(token))
            {
                DateTime start = DateTime.Now;

                TokenIntrospectionResponse response = httpClientFactory.CreateClient().IntrospectTokenAsync(new TokenIntrospectionRequest
                {
                    Address = endpoint,
                    Token = token,
                    ClientId = secret.Id,
                    ClientSecret = secret.Secret,
                }).Result;

                if (gateway.HttpServer.EnableLog(LogType.Debug))
                    gateway.HttpServer.Log(LogType.Error, $"get claims times : {(DateTime.Now - start).TotalMilliseconds}ms");

                if (!response.IsError && response.IsActive)
                {
                    return response.Claims.Select(c => new ClaimInfo { Type = c.Type, Value = c.Value }).ToList();
                }
                else
                {
                    if (gateway.HttpServer.EnableLog(LogType.Debug))
                        gateway.HttpServer.Log(LogType.Error, "Reference error:" + response.Error);
                }
            }
            else
            {
                if (gateway.HttpServer.EnableLog(LogType.Debug))
                    gateway.HttpServer.Log(LogType.Error, "jwt token is empty");
            }
            return new List<ClaimInfo>();
        }
    }


}
