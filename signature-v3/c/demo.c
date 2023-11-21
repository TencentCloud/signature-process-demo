#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

void get_utc_date(int64_t timestamp, char* utc, int len)
{
    // time_t timenow;
    struct tm sttime;
    sttime = *gmtime(&timestamp);
    strftime(utc, len, "%Y-%m-%d", &sttime);
}

void sha256_hex(const char* str, char* result)
{
    char buf[3];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(hash, &sha256);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        strcat(result, buf);
    }
}

void hmac_sha256(char* key, const char* input, char* result)
{
    unsigned char hash[32];

    HMAC_CTX *h;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    h = &hmac;
#else
    h = HMAC_CTX_new();
#endif

    HMAC_Init_ex(h, key, strlen(key), EVP_sha256(), NULL);
    HMAC_Update(h, ( unsigned char* )input, strlen(input));
    unsigned int len = 32;
    HMAC_Final(h, hash, &len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(h);
#else
    HMAC_CTX_free(h);
#endif
    strncpy(result, (const char*)hash, len);
}

void hex_encode(const char* input, char* output)
{
    static const char* const lut = "0123456789abcdef";
    size_t len = strlen(input);
    char add_out[128] = {0};
    char temp[2] = {0};
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        temp[0] = lut[c >> 4];
        strcat(add_out, temp);
        temp[0] = lut[c & 15];
        strcat(add_out, temp);
    }
    strncpy(output, add_out, 128);
}

void lowercase(const char * src, char * dst)
{
    for (int i = 0; src[i]; i++)
    {
        dst[i] = tolower(src[i]);
    }
}

int main()
{
    // 密钥参数
    // 需要设置环境变量 TENCENTCLOUD_SECRET_ID，值为示例的 AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******
    const char* SECRET_ID = getenv("TENCENTCLOUD_SECRET_ID");
    // 需要设置环境变量 TENCENTCLOUD_SECRET_KEY，值为示例的 Gu5t9xGARNpq86cd98joQYCN3*******
    const char* SECRET_KEY = getenv("TENCENTCLOUD_SECRET_KEY");
    const char* service = "cvm";
    const char* host = "cvm.tencentcloudapi.com";
    const char* region = "ap-guangzhou";
    const char* action = "DescribeInstances";
    const char* version = "2017-03-12";
    int64_t timestamp = 1551113065;
    char date[20] = {0};
    get_utc_date(timestamp, date, sizeof(date));

    // ************* 步骤 1：拼接规范请求串 *************
    const char* http_request_method = "POST";
    const char* canonical_uri = "/";
    const char* canonical_query_string = "";
    char canonical_headers[100] = {"content-type:application/json; charset=utf-8\nhost:"};
    strcat(canonical_headers, host);
    strcat(canonical_headers, "\nx-tc-action:");
    char value[100] = {0};
    lowercase(action, value);
    strcat(canonical_headers, value);
    strcat(canonical_headers, "\n");
    const char* signed_headers = "content-type;host;x-tc-action";
    const char* payload = "{\"Limit\": 1, \"Filters\": [{\"Values\": [\"\\u672a\\u547d\\u540d\"], \"Name\": \"instance-name\"}]}";
    char hashed_request_payload[100] = {0};
    sha256_hex(payload, hashed_request_payload);

    char canonical_request[256] = {0};
    sprintf(canonical_request, "%s\n%s\n%s\n%s\n%s\n%s", http_request_method,
            canonical_uri, canonical_query_string, canonical_headers,
            signed_headers, hashed_request_payload);
    printf("%s\n", canonical_request);


    // ************* 步骤 2：拼接待签名字符串 *************
    const char*  algorithm = "TC3-HMAC-SHA256";
    char request_timestamp[16] = {0};
    sprintf(request_timestamp, "%ld", timestamp);
    char credential_scope[64] = {0};
    strcat(credential_scope, date);
    sprintf(credential_scope, "%s/%s/tc3_request", date, service);
    char hashed_canonical_request[100] = {0};
    sha256_hex(canonical_request, hashed_canonical_request);
    char string_to_sign[256] = {0};
    sprintf(string_to_sign, "%s\n%s\n%s\n%s", algorithm, request_timestamp,
            credential_scope, hashed_canonical_request);
    printf("%s\n", string_to_sign);

    // ************* 步骤 3：计算签名 ***************
    char k_key[64] = {0};
    sprintf(k_key, "%s%s", "TC3", SECRET_KEY);
    char k_date[64] = {0};
    hmac_sha256(k_key, date, k_date);
    char k_service[64] = {0};
    hmac_sha256(k_date, service, k_service);
    char k_signing[64] = {0};
    hmac_sha256(k_service, "tc3_request", k_signing);
    char k_hmac_sha_sign[64] = {0};
    hmac_sha256(k_signing, string_to_sign, k_hmac_sha_sign);

    char signature[128] = {0};
    hex_encode(k_hmac_sha_sign, signature);
    printf("%s\n", signature);

    // ************* 步骤 4：拼接 Authorization *************
    char authorization[512] = {0};
    sprintf(authorization, "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
            algorithm, SECRET_ID, credential_scope, signed_headers, signature);
    printf("%s\n", authorization);

    char curlcmd[10240] = {0};
    sprintf(curlcmd, "curl -X POST https://%s\\\n \
            -H \"Authorization: %s\"\\\n \
            -H \"Content-Type: application/json; charset=utf-8\"\\\n \
            -H \"Host: %s\"\\\n \
            -H \"X-TC-Action: %s\"\\\n \
            -H \"X-TC-Timestamp: %s\"\\\n \
            -H \"X-TC-Version: %s\"\\\n \
            -H \"X-TC-Region: %s\"\\\n \
            -d \'%s\'",
            host, authorization, host, action, request_timestamp, version, region, payload);
    printf("%s\n", curlcmd);
    return 0;
}
