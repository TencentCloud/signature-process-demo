import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Random;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class TencentCloudAPIDemo {
    private final static String CHARSET = "UTF-8";
    // 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
    private final static String SECRET_ID = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******";
    private final static String SECRET_KEY = "Gu5t9xGARNpq86cd98joQYCN3*******";

    public static String sign(String s, String key, String method) throws Exception {
        Mac mac = Mac.getInstance(method);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(CHARSET), mac.getAlgorithm());
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(s.getBytes(CHARSET));
        return DatatypeConverter.printBase64Binary(hash);
    }

    public static String getStringToSign(TreeMap<String, Object> params) {
        StringBuilder s2s = new StringBuilder("GETsms.tencentcloudapi.com/?");
        // 签名时要求对参数进行字典排序，此处用TreeMap保证顺序
        for (String k : params.keySet()) {
            s2s.append(k).append("=").append(params.get(k).toString()).append("&");
        }
        return s2s.toString().substring(0, s2s.length() - 1);
    }

    public static String getUrl(TreeMap<String, Object> params) throws UnsupportedEncodingException {
        StringBuilder url = new StringBuilder("https://sms.tencentcloudapi.com/?");
        // 实际请求的url中对参数顺序没有要求
        for (String k : params.keySet()) {
            // 需要对请求串进行urlencode，由于key都是英文字母，故此处仅对其value进行urlencode
            url.append(k).append("=").append(URLEncoder.encode(params.get(k).toString(), CHARSET)).append("&");
        }
        return url.toString().substring(0, url.length() - 1);
    }

    public static void main(String[] args) throws Exception {
        TreeMap<String, Object> params = new TreeMap<String, Object>(); // TreeMap可以自动排序
        // 实际调用时应当使用随机数，例如：params.put("Nonce", new Random().nextInt(java.lang.Integer.MAX_VALUE));
        params.put("Nonce", 11886); // 公共参数
        params.put("Timestamp", System.currentTimeMillis() / 1000);
        params.put("SecretId", SECRET_ID); // 公共参数
        params.put("Action", "SendSms"); // 公共参数
        params.put("Version", "2021-01-11"); // 公共参数
        params.put("Region", "ap-guangzhou"); // 公共参数
        // 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
        params.put("SmsSdkAppId", "1400006666"); // 业务参数
        params.put("TemplateId", "1234"); // 业务参数
        params.put("TemplateParamSet.0", "12345"); // 业务参数
        params.put("PhoneNumberSet.0", "+8618511122266"); // 业务参数
        params.put("SessionContext", "test"); // 业务参数
        params.put("Signature", sign(getStringToSign(params), SECRET_KEY, "HmacSHA1")); // 公共参数
        System.out.println("curl '" + getUrl(params) + "'");
    }
}
