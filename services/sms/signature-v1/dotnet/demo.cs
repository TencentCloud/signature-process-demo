using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Net;

public class Application {
    public static string Sign(string signKey, string secret)
    {
        string signRet = string.Empty;
            using (HMACSHA1 mac = new HMACSHA1(Encoding.UTF8.GetBytes(signKey)))
            {
                byte[] hash = mac.ComputeHash(Encoding.UTF8.GetBytes(secret));
                signRet = Convert.ToBase64String(hash);
            }
        return signRet;
    }
    public static string MakeSignPlainText(SortedDictionary<string, string> requestParams, string requestMethod, string requestHost, string requestPath)
    {
        string retStr = "";
        retStr += requestMethod;
        retStr += requestHost;
        retStr += requestPath;
        retStr += "?";
        string v = "";
        foreach (string key in requestParams.Keys)
        {
            v += string.Format("{0}={1}&", key, requestParams[key]);
        }
        retStr += v.TrimEnd('&');
        return retStr;
    }

    public static long ToTimestamp()
    {
        DateTime startTime = new System.DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        DateTime nowTime = DateTime.UtcNow;
        long unixTime = (long)Math.Round((nowTime - startTime).TotalMilliseconds, MidpointRounding.AwayFromZero);
        return unixTime;

    }

    public static void Main(string[] args)
    {
        // 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
        string SECRET_ID = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******";
        string SECRET_KEY = "Gu5t9xGARNpq86cd98joQYCN3*******";

        string endpoint = "sms.tencentcloudapi.com";
        string region = "ap-guangzhou";
        string action = "SendSms";
        string version = "2021-01-11";
        // double requestTimestamp = 1465185768;  // 时间戳 2019-02-26 00:44:25,此参数作为示例，以实际为准
        long timestamp = ToTimestamp() / 1000;
        string requestTimestamp = timestamp.ToString();
        Dictionary<string, string> param = new Dictionary<string, string>();
        param.Add("Action", action);
        // param.Add("Nonce", "11886");
        param.Add("Nonce", Math.Abs(new Random().Next()).ToString());

        param.Add("Timestamp", requestTimestamp.ToString());
        param.Add("Version", version);

        param.Add("SecretId", SECRET_ID);
        param.Add("Region", region);
        // 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
        param.Add("SmsSdkAppId", "1400006666");
        param.Add("SignName", "腾讯云");
        param.Add("TemplateId", "1234");
        param.Add("TemplateParamSet.0", "12345");
        param.Add("PhoneNumberSet.0", "+8618511122266");
        param.Add("SessionContext", "test");
        SortedDictionary<string, string> headers = new SortedDictionary<string, string>(param, StringComparer.Ordinal);
        string sigInParam = MakeSignPlainText(headers, "GET", endpoint, "/");
        string sigOutParam = Sign(SECRET_KEY, sigInParam);
        Console.WriteLine(sigOutParam); // 输出签名

        // 获取 curl 命令串
        param.Add("Signature", sigOutParam);
        StringBuilder urlBuilder = new StringBuilder();
        foreach (KeyValuePair<string, string> kvp in param)
        {
            urlBuilder.Append($"{WebUtility.UrlEncode(kvp.Key)}={WebUtility.UrlEncode(kvp.Value)}&");
        }
        string query = urlBuilder.ToString().TrimEnd('&');

        string url = "https://" + endpoint + "/?" + query;
        string curlcmd = "curl \"" + url + "\"";
        Console.WriteLine(curlcmd);
    }
}