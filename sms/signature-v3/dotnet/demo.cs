using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public class Application
{
    public static string SHA256Hex(string s)
    {
        using (SHA256 algo = SHA256.Create())
        {
            byte[] hashbytes = algo.ComputeHash(Encoding.UTF8.GetBytes(s));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < hashbytes.Length; ++i)
            {
                builder.Append(hashbytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }

    public static byte[] HmacSHA256(byte[] key, byte[] msg)
    {
        using (HMACSHA256 mac = new HMACSHA256(key))
        {
            return mac.ComputeHash(msg);
        }
    }

    public static Dictionary<String, String> BuildHeaders(string secretid,
        string secretkey, string service, string endpoint, string region,
        string action, string version, DateTime date, string requestPayload)
    {
        string datestr = date.ToString("yyyy-MM-dd");
        DateTime startTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        long requestTimestamp = (long)Math.Round((date - startTime).TotalMilliseconds, MidpointRounding.AwayFromZero) / 1000;
        // ************* 步骤 1：拼接规范请求串 *************
        string algorithm = "TC3-HMAC-SHA256";
        string httpRequestMethod = "POST";
        string canonicalUri = "/";
        string canonicalQueryString = "";
        string contentType = "application/json";
        string canonicalHeaders = "content-type:" + contentType + "; charset=utf-8\n" + "host:" + endpoint + "\n";
        string signedHeaders = "content-type;host";
        string hashedRequestPayload = SHA256Hex(requestPayload);
        string canonicalRequest = httpRequestMethod + "\n"
            + canonicalUri + "\n"
            + canonicalQueryString + "\n"
            + canonicalHeaders + "\n"
            + signedHeaders + "\n"
            + hashedRequestPayload;
        Console.WriteLine(canonicalRequest);

        // ************* 步骤 2：拼接待签名字符串 *************
        string credentialScope = datestr + "/" + service + "/" + "tc3_request";
        string hashedCanonicalRequest = SHA256Hex(canonicalRequest);
        string stringToSign = algorithm + "\n" + requestTimestamp.ToString() + "\n" + credentialScope + "\n" + hashedCanonicalRequest;
        Console.WriteLine(stringToSign);

        // ************* 步骤 3：计算签名 *************
        byte[] tc3SecretKey = Encoding.UTF8.GetBytes("TC3" + secretkey);
        byte[] secretDate = HmacSHA256(tc3SecretKey, Encoding.UTF8.GetBytes(datestr));
        byte[] secretService = HmacSHA256(secretDate, Encoding.UTF8.GetBytes(service));
        byte[] secretSigning = HmacSHA256(secretService, Encoding.UTF8.GetBytes("tc3_request"));
        byte[] signatureBytes = HmacSHA256(secretSigning, Encoding.UTF8.GetBytes(stringToSign));
        string signature = BitConverter.ToString(signatureBytes).Replace("-", "").ToLower();
        Console.WriteLine(signature);

        // ************* 步骤 4：拼接 Authorization *************
        string authorization = algorithm + " "
            + "Credential=" + secretid + "/" + credentialScope + ", "
            + "SignedHeaders=" + signedHeaders + ", "
            + "Signature=" + signature;
        Console.WriteLine(authorization);

        Dictionary<string, string> headers = new Dictionary<string, string>();
        headers.Add("Authorization", authorization);
        headers.Add("Host", endpoint);
        headers.Add("Content-Type", contentType + "; charset=utf-8");
        headers.Add("X-TC-Timestamp", requestTimestamp.ToString());
        headers.Add("X-TC-Version", version);
        headers.Add("X-TC-Action", action);
        headers.Add("X-TC-Region", region);
        return headers;
    }
    public static void Main(string[] args)
    {
        // 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
        string SECRET_ID = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******";
        string SECRET_KEY = "Gu5t9xGARNpq86cd98joQYCN3*******";

        string service = "sms";
        string endpoint = "sms.tencentcloudapi.com";
        string region = "ap-guangzhou";
        string action = "SendSms";
        string version = "2021-01-11";

        // 此处由于示例规范的原因，采用时间戳2019-02-26 00:44:25，此参数作为示例，如果在项目中，您应当使用：
        DateTime date = DateTime.UtcNow;
        // 注意时区，建议此时间统一采用UTC时间戳，否则容易出错
        // DateTime date = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(1551113065);
        // 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
        string requestPayload = "{\"SmsSdkAppId\":\"1400006666\",\"TemplateParamSet\":[\"12345\"],\"PhoneNumberSet\":[\"+8618511122266\"],\"SessionContext\":\"test\",\"SignName\":\"腾讯云\",\"TemplateId\":\"1234\"}";

        Dictionary<string, string> headers = BuildHeaders(SECRET_ID, SECRET_KEY, service
            , endpoint, region, action, version, date, requestPayload);

        Console.WriteLine("POST https://sms.tencentcloudapi.com");
        foreach (KeyValuePair<string, string> kv in headers)
        {
            Console.WriteLine(kv.Key + ": " + kv.Value);
        }
        Console.WriteLine();
        Console.WriteLine(requestPayload);

        string curlcmd = "curl -X POST https://" + endpoint;
        foreach (KeyValuePair<string, string> kv in headers)
        {
            curlcmd = curlcmd + " -H \"" + kv.Key + ": " + kv.Value + "\"";
        }
        curlcmd = curlcmd + " -d '" + requestPayload + "'";
        Console.WriteLine(curlcmd);              
    }
}