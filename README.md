# auto-cert-alidns

```bash
auto-cert-alidns \
        --email=me@example.com \
        --access-key=your-access-key-id \
        --secret-key=your-access-key-secret \
        --domain=example.com \
        --subs=www \
        --subs=api \
        --subs='*' \
        --output=/etc/certmagic
```

基于 `github.com/caddyserver/certmagic` 和 `github.com/libdns/alidns`，通过 DNS-01 (`TXT`) 自动申请并续期证书。

证书申请成功后，程序会把证书和私钥导出到：

```text
<output>/exported/<domain>.crt
<output>/exported/<domain>.key
```

通配符域名会被转换为文件名 `wildcard.example.com.crt`/`wildcard.example.com.key`。

## 参数

- `--email` ACME 账号邮箱。
- `--access-key` 阿里云 AccessKeyID。
- `--secret-key` 阿里云 AccessKeySecret。
- `--domain` 主域名，例如 `example.com`。
- `--subs` 子域名前缀，支持重复传参、逗号分隔，支持 `*` 和 `@`。
- `--output` 输出目录（certmagic 存储目录和导出目录的根目录）。
- `--region` 阿里云区域，默认 `cn-hangzhou`。
- `--include-root` 是否包含根域名，默认 `true`。
- `--staging` 是否使用 Let's Encrypt 测试环境，默认 `false`。
- `--dns-resolver` 可选，自定义 DNS 解析器（可重复传参），例如 `223.5.5.5:53`。
- `--dns-ttl` ACME 临时 TXT 记录 TTL，默认 `2m`。
- `--dns-propagation-delay` 检查 DNS 传播前等待时间，默认 `10s`。
- `--dns-propagation-timeout` DNS 传播检查超时，默认 `3m`。

## 示例

只申请根域名和几个子域名：

```bash
auto-cert-alidns \
    --email=me@example.com \
    --access-key=xxx \
    --secret-key=xxx \
    --domain=example.com \
    --subs=www,api,git \
    --output=./cert-data
```

申请通配符证书（包含根域名）：

```bash
auto-cert-alidns \
    --email=me@example.com \
    --access-key=xxx \
    --secret-key=xxx \
    --domain=example.com \
    --subs='*' \
    --include-root=true \
    --output=./cert-data
```

## ARM64

```
GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w"
```
