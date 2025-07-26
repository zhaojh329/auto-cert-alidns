package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/alidns"
	"github.com/urfave/cli/v3"
)

const version = "1.1.0"

type appConfig struct {
	Email                 string
	AccessKey             string
	SecretKey             string
	Domain                string
	Subs                  []string
	Output                string
	Region                string
	IncludeRoot           bool
	UseStagingCA          bool
	DNSResolvers          []string
	DNSTTL                time.Duration
	DNSPropagationDelay   time.Duration
	DNSPropagationTimeout time.Duration
}

func main() {
	cmd := &cli.Command{
		Name:      "auto-cert-alidns",
		Usage:     "Automatically obtain TLS certificates with CertMagic and AliDNS TXT verification",
		ArgsUsage: `--email=test@example.com --access-key=xxx --secret-key=xxx --domain=example.com --subs=www --subs=api --output=/etc/certmagic`,
		Version:   version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "email",
				Usage:    "ACME account email",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "access-key",
				Usage:    "AliDNS AccessKeyID",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "secret-key",
				Usage:    "AliDNS AccessKeySecret",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "domain",
				Usage:    "Primary domain, e.g. example.com",
				Required: true,
			},
			&cli.StringSliceFlag{
				Name:  "subs",
				Usage: "Sub domain entries. Supports repeated flags and comma-separated values. Examples: www,api,*",
			},
			&cli.StringFlag{
				Name:     "output",
				Usage:    "Storage directory for certmagic assets and exported certs",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "region",
				Usage: "AliDNS region",
				Value: "cn-hangzhou",
			},
			&cli.BoolFlag{
				Name:  "include-root",
				Usage: "Include the root domain itself in the certificate list",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "staging",
				Usage: "Use Let's Encrypt staging environment",
				Value: false,
			},
			&cli.StringSliceFlag{
				Name:  "dns-resolver",
				Usage: "Custom DNS resolvers for propagation checks, format host:port, can be repeated",
			},
			&cli.DurationFlag{
				Name:  "dns-ttl",
				Usage: "TTL for temporary ACME TXT records",
				Value: 2 * time.Minute,
			},
			&cli.DurationFlag{
				Name:  "dns-propagation-delay",
				Usage: "Delay before DNS propagation checks",
				Value: 10 * time.Second,
			},
			&cli.DurationFlag{
				Name:  "dns-propagation-timeout",
				Usage: "Timeout for DNS propagation checks",
				Value: 3 * time.Minute,
			},
		},
		Action: cmdAction,
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func cmdAction(c context.Context, cmd *cli.Command) error {
	conf := appConfig{
		Email:                 strings.TrimSpace(cmd.String("email")),
		AccessKey:             strings.TrimSpace(cmd.String("access-key")),
		SecretKey:             strings.TrimSpace(cmd.String("secret-key")),
		Domain:                strings.TrimSpace(cmd.String("domain")),
		Subs:                  cmd.StringSlice("subs"),
		Output:                strings.TrimSpace(cmd.String("output")),
		Region:                strings.TrimSpace(cmd.String("region")),
		IncludeRoot:           cmd.Bool("include-root"),
		UseStagingCA:          cmd.Bool("staging"),
		DNSResolvers:          cmd.StringSlice("dns-resolver"),
		DNSTTL:                cmd.Duration("dns-ttl"),
		DNSPropagationDelay:   cmd.Duration("dns-propagation-delay"),
		DNSPropagationTimeout: cmd.Duration("dns-propagation-timeout"),
	}

	if conf.Output == "" {
		return fmt.Errorf("--output must not be empty")
	}

	absOutput, err := filepath.Abs(conf.Output)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	conf.Output = absOutput

	domains, err := buildDomains(conf.Domain, conf.Subs, conf.IncludeRoot)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(conf.Output, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	log.Printf("requesting certificates for %v", domains)
	log.Printf("certmagic storage path: %s", conf.Output)

	storage := &certmagic.FileStorage{Path: conf.Output}
	var magic *certmagic.Config
	certCache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			if magic == nil {
				return nil, fmt.Errorf("certmagic config is not initialized")
			}
			return magic, nil
		},
	})
	defer certCache.Stop()

	magic = certmagic.New(certCache, certmagic.Config{Storage: storage})

	provider := &alidns.Provider{
		CredentialInfo: alidns.CredentialInfo{
			AccessKeyID:     conf.AccessKey,
			AccessKeySecret: conf.SecretKey,
			RegionID:        conf.Region,
		},
	}

	caEndpoint := certmagic.LetsEncryptProductionCA
	if conf.UseStagingCA {
		caEndpoint = certmagic.LetsEncryptStagingCA
	}

	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      caEndpoint,
		Email:                   conf.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider:        provider,
				TTL:                conf.DNSTTL,
				PropagationDelay:   conf.DNSPropagationDelay,
				PropagationTimeout: conf.DNSPropagationTimeout,
				Resolvers:          normalizeStringSlice(conf.DNSResolvers),
				OverrideDomain:     "",
			},
		},
	})

	magic.Issuers = []certmagic.Issuer{issuer}

	if err := magic.ManageSync(c, domains); err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}

	exportDir := filepath.Join(conf.Output, "exported")
	if err := exportIssuedCertificates(c, storage, issuer.IssuerKey(), domains, exportDir); err != nil {
		return err
	}

	log.Printf("certificate request finished, exported files are in: %s", exportDir)
	return nil
}

func buildDomains(baseDomain string, rawSubs []string, includeRoot bool) ([]string, error) {
	baseDomain = strings.Trim(strings.TrimSpace(baseDomain), ".")
	if baseDomain == "" {
		return nil, fmt.Errorf("domain must not be empty")
	}

	set := make(map[string]struct{})
	if includeRoot {
		set[baseDomain] = struct{}{}
	}

	for _, sub := range normalizeStringSlice(rawSubs) {
		name, err := resolveDomain(baseDomain, sub)
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		set[name] = struct{}{}
	}

	if len(set) == 0 {
		return nil, fmt.Errorf("no domains to request, please set --subs or enable --include-root")
	}

	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeStringSlice(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.Trim(strings.TrimSpace(part), "\"'")
			if part == "" {
				continue
			}
			result = append(result, part)
		}
	}
	return result
}

func resolveDomain(baseDomain, sub string) (string, error) {
	sub = strings.Trim(strings.TrimSpace(sub), ".")
	if sub == "" {
		return "", nil
	}

	switch sub {
	case "@":
		return baseDomain, nil
	case "*":
		return "*." + baseDomain, nil
	}

	if strings.Contains(sub, "*") && !strings.HasPrefix(sub, "*.") {
		return "", fmt.Errorf("invalid sub domain %q", sub)
	}

	if sub == baseDomain || strings.HasSuffix(sub, "."+baseDomain) {
		return sub, nil
	}

	if strings.HasPrefix(sub, "*.") {
		suffix := strings.TrimPrefix(sub, "*.")
		if suffix == "" {
			return "", fmt.Errorf("invalid wildcard sub domain %q", sub)
		}
		if suffix == baseDomain || strings.HasSuffix(suffix, "."+baseDomain) {
			return "*." + suffix, nil
		}
		return "*." + suffix + "." + baseDomain, nil
	}

	return sub + "." + baseDomain, nil
}

func exportIssuedCertificates(ctx context.Context, storage certmagic.Storage, issuerKey string, domains []string, exportDir string) error {
	if err := os.MkdirAll(exportDir, 0o700); err != nil {
		return fmt.Errorf("create export directory: %w", err)
	}

	replacer := strings.NewReplacer("*", "wildcard", "/", "_", "\\", "_")
	for _, domain := range domains {
		certStorageKey := certmagic.StorageKeys.SiteCert(issuerKey, domain)
		keyStorageKey := certmagic.StorageKeys.SitePrivateKey(issuerKey, domain)

		certPEM, err := storage.Load(ctx, certStorageKey)
		if err != nil {
			return fmt.Errorf("load certificate from storage for %s: %w", domain, err)
		}
		keyPEM, err := storage.Load(ctx, keyStorageKey)
		if err != nil {
			return fmt.Errorf("load private key from storage for %s: %w", domain, err)
		}

		fileBase := replacer.Replace(domain)
		certFile := filepath.Join(exportDir, fileBase+".crt")
		keyFile := filepath.Join(exportDir, fileBase+".key")

		if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
			return fmt.Errorf("write certificate file for %s: %w", domain, err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			return fmt.Errorf("write key file for %s: %w", domain, err)
		}

		log.Printf("exported %s -> %s, %s", domain, certFile, keyFile)
	}

	return nil
}
