# Qbcode.IDS4
Bumblebee网关的IdentityServer4统一验证插件，插件使用的前提是你已经有了一identity server4的证书颁发中心，可以使得程序可以获得端点信息

# 使用
## 1，加载插件
```
g = new Gateway();
....省略一万字
g.LoadPlugin(
                  typeof(Qbcode.IDS4.Plugin).Assembly
               );
```
## 2，启用插件并配置认证信息
```
{
   //默认的api id
    "DefaultId": "default",
    //默认的api 密码
    "DefaultSecret": "apisecret",
    //证书颁发中心
    "Authority": "http://localhost:5000",
    //是否认证颁发中心，证书可能来自不同的颁发中心，是否阻止别的颁发中心的证书被认证
    "Issuer":false,
    //Reference token的缓存时间 秒 应该有也不应该太长
    "CacheDuration": 10,
    //token在headers里的key
    "TokenKey": "Authorization",
    //那些页面后缀不验证
    "ExSuffix": [
        "ico",
        "jpg",
        "gif",
        "png",
        "js",
        "css",
        "wav",
        "mp3"
    ],
    //验证规则
    "Policys": [
        {
            //起个名字
            "Name": "default",
            //claim规则 
            "Claim": [
                {
                   //验证哪个claim
                    "Key": "",
                    //需要哪些值  如果不填写 则只要存在key配置的名字的claim即可验证成功
                    "Values": []
                }
            ],
            //允许哪些scope(也就是认证中心颁发给某个api的apiName)  多个为并且的关系 也就是全部都要存在， 在claim规则中配置key为aud的claim验证也是一样的效果
            "Scopes": [
                "user"
            ]
        }
    ],
    //配置哪些url需要验证
    "Urls": [
        {
            "Url": "^/index.*",
            //apiName
            "Id": "default",
            //apiSecret
            "Secret": "apisecret",
            //使用哪个验证规则
            "Policy": "default"
        }
    ]
}

```
