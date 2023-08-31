package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha1"
    "encoding/base64"
    "fmt"
    "sort"
    "strconv"
)

func main() {
    secretId := "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
    secretKey := "Gu5t9xGARNpq86cd98joQYCN3*******"
    params := map[string]string{
        "Nonce":         "11886",
        "Timestamp":     strconv.Itoa(1465185768),
        "Region":        "ap-guangzhou",
        "SecretId":      secretId,
        "Version":       "2017-03-12",
        "Action":        "DescribeInstances",
        "InstanceIds.0": "ins-09dx96dg",
        "Limit":         strconv.Itoa(20),
        "Offset":        strconv.Itoa(0),
    }

    var buf bytes.Buffer
    buf.WriteString("GET")
    buf.WriteString("cvm.tencentcloudapi.com")
    buf.WriteString("/")
    buf.WriteString("?")

    // sort keys by ascii asc order
    keys := make([]string, 0, len(params))
    for k, _ := range params {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    for i := range keys {
        k := keys[i]
        buf.WriteString(k)
        buf.WriteString("=")
        buf.WriteString(params[k])
        buf.WriteString("&")
    }
    buf.Truncate(buf.Len() - 1)

    hashed := hmac.New(sha1.New, []byte(secretKey))
    hashed.Write(buf.Bytes())

    fmt.Println(base64.StdEncoding.EncodeToString(hashed.Sum(nil)))
}
