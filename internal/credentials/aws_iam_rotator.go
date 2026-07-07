package credentials

// aws_iam_rotator.go — AWS IAM access-key rotation connector.
//
// This connector manages a DEDICATED, rotation-managed IAM user's access keys.
// It implements Minter (mint the new key directly via IAM API), Verify (STS
// GetCallerIdentity with retry for eventual consistency), PostRotateCleaner
// (delete all but the newest key after promotion), and ConfigValidator.
//
// CONSTRAINT: Apply is a no-op. The minted key value is JSON-encoded awsCreds;
// the admin secret must also be JSON-encoded awsCreds. The target IAM user should
// be dedicated to rotation (no other code rotates its keys). AWS IAM allows at
// most 2 access keys per user; Mint deletes the oldest when the limit is reached.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// awsCreds is the JSON shape for both the admin secret and the rotated value.
//
// Note: the raw vault bytes are wiped via zero() after decoding, but the decoded
// AccessKeyID/SecretAccessKey are Go strings (immutable — cannot be wiped in place) and
// are handed to the aws-sdk-go-v2 static-credentials provider, which requires strings.
// Their lifetime is bounded to the Mint/Cleanup call; there is no log path for them.
type awsCreds struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// iamAPI is the subset of *iam.Client used by the connector. Defined as an
// interface so tests can substitute a fake without network access.
type iamAPI interface {
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(ctx context.Context, in *iam.CreateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(ctx context.Context, in *iam.DeleteAccessKeyInput, optFns ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}

// stsAPI is the subset of *sts.Client used by the connector.
type stsAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// awsIAMConf holds the parsed, validated fields from an aws_iam connector_config map.
type awsIAMConf struct {
	targetUser    string
	adminSecretID string
	region        string
}

// awsIAMConfigFromMap parses and validates an aws_iam connector_config map.
// Required: target_user, admin_secret_id. Default: region="us-east-1".
func awsIAMConfigFromMap(cfg map[string]any) (awsIAMConf, error) {
	str := func(key string) string {
		v, _ := cfg[key].(string)
		return v
	}

	targetUser := str("target_user")
	adminSecretID := str("admin_secret_id")

	switch {
	case targetUser == "":
		return awsIAMConf{}, fmt.Errorf("aws_iam connector: missing required field %q", "target_user")
	case adminSecretID == "":
		return awsIAMConf{}, fmt.Errorf("aws_iam connector: missing required field %q", "admin_secret_id")
	}

	region := str("region")
	if region == "" {
		region = "us-east-1"
	}

	return awsIAMConf{
		targetUser:    targetUser,
		adminSecretID: adminSecretID,
		region:        region,
	}, nil
}

// awsIAMRotator rotates an IAM user's access keys. It implements Rotator,
// Minter, PostRotateCleaner, and ConfigValidator.
type awsIAMRotator struct {
	vault         vaultUser
	newIAM        func(region string, creds awsCreds) iamAPI
	newSTS        func(region string, creds awsCreds) stsAPI
	verifyRetries int
	verifyDelay   time.Duration
}

// NewAWSIAMRotator returns a Rotator (also Minter/PostRotateCleaner/ConfigValidator)
// that rotates an IAM user's access keys via the AWS IAM API. vaultUser is satisfied
// by *vault.Service.
func NewAWSIAMRotator(v vaultUser) Rotator {
	return &awsIAMRotator{
		vault:         v,
		newIAM:        realIAMClient,
		newSTS:        realSTSClient,
		verifyRetries: 6,
		verifyDelay:   3 * time.Second,
	}
}

func (r *awsIAMRotator) Type() string { return "aws_iam" }

// Apply is a no-op: the Minter path mints the key directly and there is nothing
// to "apply" afterwards (the key is already live on the target IAM user).
func (r *awsIAMRotator) Apply(_ context.Context, _ map[string]any, _ []byte) error {
	return nil
}

// ValidateConfig returns an error if cfg is missing required fields.
func (r *awsIAMRotator) ValidateConfig(cfg map[string]any) error {
	_, err := awsIAMConfigFromMap(cfg)
	return err
}

// admin fetches and decodes the admin credentials from the vault.
func (r *awsIAMRotator) admin(ctx context.Context, conf awsIAMConf) (awsCreds, error) {
	raw, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil {
		return awsCreds{}, fmt.Errorf("aws_iam: fetch admin secret: %w", err)
	}
	defer zero(raw)

	var c awsCreds
	if err := json.Unmarshal(raw, &c); err != nil {
		return awsCreds{}, fmt.Errorf("aws_iam: admin secret is not valid JSON: %w", err)
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return awsCreds{}, fmt.Errorf("aws_iam: admin secret missing access_key_id or secret_access_key")
	}
	return c, nil
}

// Mint creates a new access key for the target IAM user and returns it as JSON.
// If the user already has 2 keys (AWS limit), the oldest is deleted first to make room.
// The previously-live key is NOT deleted here — Cleanup handles that after promotion.
func (r *awsIAMRotator) Mint(ctx context.Context, cfg map[string]any) ([]byte, error) {
	conf, err := awsIAMConfigFromMap(cfg)
	if err != nil {
		return nil, err
	}

	adm, err := r.admin(ctx, conf)
	if err != nil {
		return nil, err
	}

	cli := r.newIAM(conf.region, adm)

	listOut, err := cli.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(conf.targetUser)})
	if err != nil {
		return nil, fmt.Errorf("aws_iam: list access keys for %q: %w", conf.targetUser, err)
	}

	// AWS allows at most 2 access keys per user. Delete the oldest to make room.
	if len(listOut.AccessKeyMetadata) >= 2 {
		oldest := oldestKey(listOut.AccessKeyMetadata)
		if oldest != "" {
			if _, err := cli.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
				UserName:    aws.String(conf.targetUser),
				AccessKeyId: aws.String(oldest),
			}); err != nil {
				return nil, fmt.Errorf("aws_iam: delete oldest key %q: %w", oldest, err)
			}
		}
	}

	createOut, err := cli.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: aws.String(conf.targetUser),
	})
	if err != nil {
		return nil, fmt.Errorf("aws_iam: create access key for %q: %w", conf.targetUser, err)
	}

	newCreds := awsCreds{
		AccessKeyID:     aws.ToString(createOut.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(createOut.AccessKey.SecretAccessKey),
	}

	val, err := json.Marshal(newCreds)
	if err != nil {
		return nil, fmt.Errorf("aws_iam: marshal new credentials: %w", err)
	}
	return val, nil
}

// Verify calls STS GetCallerIdentity using the newly minted credentials to confirm
// they are active. It retries up to verifyRetries times (with verifyDelay between
// attempts) to absorb IAM eventual consistency.
func (r *awsIAMRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := awsIAMConfigFromMap(cfg)
	if err != nil {
		return err
	}

	var newCreds awsCreds
	if err := json.Unmarshal(newValue, &newCreds); err != nil {
		return fmt.Errorf("aws_iam: verify: new value is not valid JSON: %w", err)
	}

	cli := r.newSTS(conf.region, newCreds)

	var lastErr error
	for i := 0; i < r.verifyRetries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("aws_iam: verify cancelled: %w", ctx.Err())
			case <-time.After(r.verifyDelay):
			}
		}

		_, err := cli.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("aws_iam: verify: key not active after %d attempts: %w", r.verifyRetries, lastErr)
}

// Cleanup deletes all access keys for the target IAM user except the newest.
// This is invoked best-effort after the new credential is promoted; its error is
// logged but does not fail the rotation.
func (r *awsIAMRotator) Cleanup(ctx context.Context, cfg map[string]any) error {
	conf, err := awsIAMConfigFromMap(cfg)
	if err != nil {
		return err
	}

	adm, err := r.admin(ctx, conf)
	if err != nil {
		return err
	}

	cli := r.newIAM(conf.region, adm)

	listOut, err := cli.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(conf.targetUser)})
	if err != nil {
		return fmt.Errorf("aws_iam: cleanup list keys for %q: %w", conf.targetUser, err)
	}

	if len(listOut.AccessKeyMetadata) <= 1 {
		return nil // nothing to clean up
	}

	newest := newestKey(listOut.AccessKeyMetadata)

	for _, k := range listOut.AccessKeyMetadata {
		id := aws.ToString(k.AccessKeyId)
		if id == newest {
			continue
		}
		if _, err := cli.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			UserName:    aws.String(conf.targetUser),
			AccessKeyId: aws.String(id),
		}); err != nil {
			return fmt.Errorf("aws_iam: cleanup delete key %q: %w", id, err)
		}
	}
	return nil
}

// oldestKey returns the AccessKeyId of the key with the earliest CreateDate.
// Returns "" if the slice is empty.
func oldestKey(keys []iamtypes.AccessKeyMetadata) string {
	var oldest string
	var oldestTime time.Time
	for _, k := range keys {
		id := aws.ToString(k.AccessKeyId)
		if id == "" {
			continue
		}
		t := time.Time{}
		if k.CreateDate != nil {
			t = *k.CreateDate
		}
		if oldest == "" {
			oldest = id
			oldestTime = t
			continue
		}
		if t.Before(oldestTime) {
			oldest = id
			oldestTime = t
		}
	}
	return oldest
}

// newestKey returns the AccessKeyId of the key with the latest CreateDate.
// Returns "" if the slice is empty.
func newestKey(keys []iamtypes.AccessKeyMetadata) string {
	var newest string
	var newestTime time.Time
	for _, k := range keys {
		id := aws.ToString(k.AccessKeyId)
		if id == "" {
			continue
		}
		if k.CreateDate == nil {
			if newest == "" {
				newest = id
				newestTime = time.Time{}
			}
			continue
		}
		if newest == "" || k.CreateDate.After(newestTime) {
			newest = id
			newestTime = *k.CreateDate
		}
	}
	return newest
}

// awsConfig builds an aws.Config with static credentials for the given region.
func awsConfig(region string, c awsCreds) aws.Config {
	return aws.Config{
		Region:      region,
		Credentials: awscreds.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""),
	}
}

func realIAMClient(region string, c awsCreds) iamAPI {
	return iam.NewFromConfig(awsConfig(region, c))
}

func realSTSClient(region string, c awsCreds) stsAPI {
	return sts.NewFromConfig(awsConfig(region, c))
}
