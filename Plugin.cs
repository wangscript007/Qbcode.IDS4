using BeetleX;
using BeetleX.EventArgs;
using BeetleX.FastHttpApi;
using Bumblebee;
using Bumblebee.Events;
using Bumblebee.Plugins;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Qbcode.IDS4
{
    [RouteBinder(ApiLoader = false)]
    public class Plugin : IPlugin, IPluginStatus, IRequestingHandler, IPluginInfo
    {
        public string Name => "qbcode.ids4";

        public string Description => "identity server 4 统一验证";

        public PluginLevel Level => PluginLevel.High6;

        private bool _Enabled = false;

        public bool Enabled
        {
            get => _Enabled; set
            {
                _Enabled = value;
                LoadValitator();
            }
        }

        public string IconUrl => string.Empty;

        public string EditorUrl => string.Empty;

        public string InfoUrl => string.Empty;

        private Gateway mGateway;


        public void Execute(EventRequestingArgs e)
        {
            bool isInvalid = false, isLog = this.mGateway.HttpServer.EnableLog(LogType.Debug);

            if (setting.ExSuffix.Length > 0 && setting.ExSuffix.Contains(e.Request.Ext))
            {
                return;
            }

            if (isLog)
            {
                this.mGateway.HttpServer.Log(LogType.Debug, ":::::::identity server4  VerifyPaths:" + string.Join(",", this.VerifyPaths));
            }

            //设置了规则
            if (this.VerifyPaths != null && this.VerifyPaths.Length > 0)
            {
                //匹配到了
                MatchCacheItem match = this.MatchUrl(e.Request);

                if (match != null && match.UrlType == UrlType.Verify)
                {

                    PatternPolicyMaps.TryGetValue(match.Pattern, out PolicyInfo policy);
                    //获取到了认证信息
                    if (policy != null)
                    {
                        //获取一下秘钥
                        SecretMaps.TryGetValue(match.Pattern, out SecretInfo secret);
                        //去取 claims
                        List<ClaimInfo> claims = GetClaims(e.Request, secret);



                        if (isLog)
                        {
                            this.mGateway.HttpServer.Log(LogType.Debug, ":::::::identity server4  claims:" + JsonConvert.SerializeObject(claims.Select(c => new { c.Type, c.Value })));
                        }
                        // 没有任何claim  认证不通过
                        if (!claims.Any())
                        {
                            if (isLog)
                            {
                                this.mGateway.HttpServer.Log(LogType.Debug, ":::::::identity server4  claims is empty");
                            }

                            isInvalid = true;
                        }
                        else
                        {
                            if (setting.Issuer)
                            {
                                string issuer = claims.FirstOrDefault(c => c.Type == "issuer")?.Value ?? "";
                                if (issuer != setting.Authority)
                                {
                                    if (isLog)
                                    {
                                        this.mGateway.HttpServer.Log(LogType.Debug, ":::::::identity server4  issuer is invalid");
                                    }
                                    isInvalid = true;
                                }
                            }

                            //需要scope 验证
                            if (!isInvalid && policy.Scopes.Any())
                            {
                                if (isLog)
                                {
                                    this.mGateway.HttpServer.Log(LogType.Debug, $":::::::identity server4  need scopes:{string.Join(",", policy.Scopes)}");
                                }

                                IEnumerable<string> scopes = claims.Where(c => c.Type == "aud").Select(c => c.Value);
                                if (scopes.Intersect(policy.Scopes).Count() == 0)
                                {
                                    if (isLog)
                                    {
                                        this.mGateway.HttpServer.Log(LogType.Debug, ":::::::identity server4  scope invalid");
                                    }
                                    isInvalid = true;
                                }
                            }

                            if (!isInvalid)
                            {
                                //需要claim认证
                                if (policy.Claim.Length > 0)
                                {

                                    //并且关系  只要有一个不通过就不通过
                                    for (int i = 0; i < policy.Claim.Length; i++)
                                    {
                                        ClaimItemInfo claim = policy.Claim[i];

                                        if (isLog)
                                        {
                                            this.mGateway.HttpServer.Log(LogType.Debug, $":::::::identity server4  need claim:{claim.Key}");
                                        }

                                        string[] values = claims.Where(c => c.Type == claim.Key).Select(c => c.Value).ToArray();
                                        //当前 key下没有任何claim的值
                                        if (!values.Any())
                                        {
                                            if (isLog)
                                            {
                                                this.mGateway.HttpServer.Log(LogType.Debug, $":::::::identity server4  claim {claim.Key} is not value");
                                            }

                                            isInvalid = true;
                                            break;
                                        }
                                        //如果设置只允许哪些值，只要其中一个值不存在就不通过
                                        else if (claim.Values.Any())
                                        {
                                            if (isLog)
                                            {
                                                this.mGateway.HttpServer.Log(LogType.Debug, $":::::::identity server4  need claim values:{string.Join(",", claim.Values)}");
                                            }

                                            if (values.Intersect(claim.Values).Count() == 0)
                                            {
                                                isInvalid = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (isInvalid)
            {
                if (this.mGateway.Pluginer.RequestedEnabled)
                {
                    EventRequestCompletedArgs eventRequestCompletedArgs = new EventRequestCompletedArgs(null, e.Request, e.Response, this.mGateway, 403, null, 0L, e.Request.ID, "token is invalid");
                    this.mGateway.Pluginer.Requested(eventRequestCompletedArgs);
                }
                e.Cancel = true;
                e.ResultType = ResultType.Completed;
                e.Gateway.Response(e.Response, new NotSupportResult("Gateway token is invalid"));
                this.mGateway.RequestIncrementCompleted(e.Request, 403, (long)(TimeWatch.GetTotalMilliseconds() - e.Request.RequestTime), null);
            }
        }

        public void Init(Gateway gateway, Assembly assembly)
        {
            this.mGateway = gateway;
            gateway.HttpServer.ResourceCenter.LoadManifestResource(assembly);
        }

        private SettingInfo setting = new SettingInfo();
        public void LoadSetting(JToken setting)
        {
            if (setting != null)
            {
                this.setting = setting.ToObject<SettingInfo>();

                //需要匹配的规则
                VerifyPaths = this.setting.Urls.Select(c => c.Url).ToArray();
                //缓存 某个url规则下的 认证方式 需要claim还是需要scopes什么的
                PatternPolicyMaps.Clear();
                this.setting.Urls.ToList().ForEach(c =>
                {
                    PolicyInfo policy = this.setting.Policys.FirstOrDefault(d => d.Name == c.Policy);
                    if (policy != null)
                    {
                        PatternPolicyMaps[c.Url] = policy;
                    }

                    SecretInfo secret = new SecretInfo();
                    if (!string.IsNullOrEmpty(c.Id))
                    {
                        secret.Id = c.Id;
                        secret.Secret = c.Secret;
                    }
                    else
                    {
                        secret.Id = this.setting.DefaultId;
                        secret.Secret = this.setting.DefaultSecret;
                    }

                    SecretMaps[c.Url] = secret;

                });


                LoadValitator();

                this.mMatchCached.Clear();
                Interlocked.Exchange(ref this.mCachedSize, 0L);
            }
        }
        public object SaveSetting()
        {
            setting.ExSuffix = setting.ExSuffix.Distinct().ToArray();
            return setting;
        }

        //需要匹配的规则
        private string[] VerifyPaths;
        //规则和 验证方案对应
        private ConcurrentDictionary<string, PolicyInfo> PatternPolicyMaps = new ConcurrentDictionary<string, PolicyInfo>();
        private ConcurrentDictionary<string, SecretInfo> SecretMaps = new ConcurrentDictionary<string, SecretInfo>();
        //缓存已和列表匹配过的url
        /*
         *  ^/api/aaa/.*  那么 所有url会存一个状态  表示是否和某个正则已经匹配过了，为了下次快速获取，不需要再次正则验证
         */
        private ConcurrentDictionary<string, MatchCacheItem> mMatchCached = new ConcurrentDictionary<string, MatchCacheItem>();

        //最多缓存多少个url
        private const int CACHED_SIZE = 200000;
        //当前已缓存了多少个url
        private long mCachedSize;
        //匹配url 这个url是否需要验证
        private MatchCacheItem MatchUrl(HttpRequest request)
        {
            string sourceBaseUrl = request.GetSourceBaseUrl();

            if (this.mMatchCached.TryGetValue(sourceBaseUrl, out MatchCacheItem result))
            {
                return result;
            }
            foreach (string pattern in this.VerifyPaths)
            {
                if (Regex.IsMatch(sourceBaseUrl, pattern, RegexOptions.IgnoreCase))
                {
                    if (result == null)
                    {
                        result = new MatchCacheItem(UrlType.Verify, pattern);
                    }
                    else
                    {
                        result.UrlType = UrlType.Verify;
                        result.Pattern = pattern;
                    }
                    break;
                }
            }
            if (this.mCachedSize < CACHED_SIZE)
            {
                this.mMatchCached[sourceBaseUrl] = result;
                Interlocked.Increment(ref this.mCachedSize);
            }

            return result;
        }

        private ITokenValitator jwtValitator;
        private ITokenValitator referenceValitator;
        private List<ClaimInfo> GetClaims(HttpRequest request, SecretInfo secret)
        {
            List<ClaimInfo> claims = new List<ClaimInfo>();
            string token = request.Header[setting.TokenKey];
            if (!string.IsNullOrWhiteSpace(token))
            {
                if (token.Contains(setting.TokenType))
                {
                    token = token[setting.TokenType.Length..];
                }
                if (token.Contains('.'))
                {
                    claims = jwtValitator.GetClaims(token, secret);
                }
                else
                {
                    claims = referenceValitator.GetClaims(token, secret);
                }
            }
            return claims;
        }
        private void LoadValitator()
        {
            jwtValitator = new TokenJwt(setting.Authority, mGateway);
            referenceValitator = new TokenReference(setting.Authority, setting.CacheDuration, mGateway);
        }

    }

    internal enum UrlType
    {
        None,
        Verify
    }

    /// <summary>
    /// url匹配成功的缓存
    /// </summary>
    internal class MatchCacheItem
    {
        public UrlType UrlType = UrlType.None;
        public string Pattern = string.Empty;

        public MatchCacheItem() { }

        public MatchCacheItem(UrlType urlType, string pattern)
        {
            UrlType = urlType;
            Pattern = pattern;
        }
    }

    internal class SettingInfo
    {
        /// <summary>
        /// 默认的id
        /// </summary>
        public string DefaultId { get; set; } = string.Empty;
        /// <summary>
        /// 默认api秘钥
        /// </summary>
        public string DefaultSecret { get; set; } = string.Empty;
        /// <summary>
        /// 认证中心
        /// </summary>
        public string Authority { get; set; } = string.Empty;

        /// <summary>
        /// 是否验证颁发中心
        /// </summary>
        public bool Issuer { get; set; } = false;

        /// <summary>
        /// 缓存时间  针对于引用token
        /// </summary>
        public int CacheDuration { get; set; } = 30;
        /// <summary>
        /// token在headers里的key
        /// </summary>
        public string TokenKey { get; set; } = "Authorization";
        /// <summary>
        /// token type 后面加个空格
        /// </summary>
        public string TokenType { get; set; } = "Bearer ";
        /// <summary>
        /// 排除哪些后缀不验证
        /// </summary>
        public string[] ExSuffix { get; set; } = new string[] { "ico", "jpg", "gif", "png", "js", "css", "wav", "mp3" };
        /// <summary>
        /// 规则
        /// </summary>
        public PolicyInfo[] Policys { get; set; } = new PolicyInfo[] { };
        /// <summary>
        /// url
        /// </summary>
        public UrlInfo[] Urls { get; set; } = new UrlInfo[] { };
    }

    internal class PolicyInfo
    {
        /// <summary>
        /// 规则名称
        /// </summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>
        /// claim验证
        /// </summary>
        public ClaimItemInfo[] Claim { get; set; } = new ClaimItemInfo[] { };
        /// <summary>
        /// scope验证
        /// </summary>
        public string[] Scopes { get; set; } = new string[] { };

    }

    internal class UrlInfo
    {
        /// <summary>
        /// url正则
        /// </summary>
        public string Url { get; set; } = string.Empty;
        /// <summary>
        /// api id
        /// </summary>
        public string Id { get; set; } = string.Empty;
        /// <summary>
        /// api秘钥
        /// </summary>
        public string Secret { get; set; } = string.Empty;
        /// <summary>
        /// 用哪个规则
        /// </summary>
        public string Policy { get; set; } = string.Empty;
    }

    internal class ClaimItemInfo
    {
        /// <summary>
        /// claim的 type 
        /// </summary>
        public string Key { get; set; } = string.Empty;
        /// <summary>
        /// 允许哪些值
        /// </summary>
        public string[] Values { get; set; } = new string[] { };
    }
}
