package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"time"
)

func main() {
	// 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
	secretId := "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
	secretKey := "Gu5t9xGARNpq86cd98joQYCN3*******"
	// 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
	params := map[string]string{
		"Nonce":              "11886",
		"Timestamp":          strconv.FormatInt(time.Now().Unix(), 10),
		"Region":             "ap-guangzhou",
		"SecretId":           secretId,
		"Version":            "2021-01-11",
		"Action":             "SendSms",
		"SmsSdkAppId":        "1400006666",
		"SignName":           "腾讯云",
		"TemplateId":         "1234",
		"TemplateParamSet.0": "12345",
		"PhoneNumberSet.0":   "+8618511122266",
		"SessionContext":     "test",
	}

	host := "sms.tencentcloudapi.com"

	var buf bytes.Buffer
	buf.WriteString("GET")
	buf.WriteString(host)
	buf.WriteString("/")
	buf.WriteString("?")

	// 1. 对参数排序,并拼接请求字符串
	keys := make([]string, 0, len(params))
	for k, _ := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 2. 拼接签名原文字符串
	for i := range keys {
		k := keys[i]
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(params[k])
		buf.WriteString("&")
	}
	buf.Truncate(buf.Len() - 1)

	// 3. 生成签名串
	hashed := hmac.New(sha1.New, []byte(secretKey))
	hashed.Write(buf.Bytes())
	signature := base64.StdEncoding.EncodeToString(hashed.Sum(nil))
	params["Signature"] = signature
	fmt.Println(signature)

	// 4. 进行url编码并拼接请求url
	var payload bytes.Buffer
	for k, v := range params {
		payload.WriteString(k)
		payload.WriteString("=")
		payload.WriteString(url.QueryEscape(v))
		payload.WriteString("&")
	}
	payload.Truncate(payload.Len() - 1)

	curl := fmt.Sprintf(`curl 'https://%s/?%s'`, host, payload.Bytes())
	fmt.Println(curl)
}