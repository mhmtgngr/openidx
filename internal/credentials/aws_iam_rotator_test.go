package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type staticVault struct{ val []byte }

func (s staticVault) Use(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.val...), nil
}

type fakeIAM struct {
	keys      []iamtypes.AccessKeyMetadata
	created   *iamtypes.AccessKey
	deleted   []string
	createErr error
}

func (f *fakeIAM) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.keys}, nil
}
func (f *fakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	ak := &iamtypes.AccessKey{AccessKeyId: aws.String("AKIANEW"), SecretAccessKey: aws.String("newsecret"), UserName: in.UserName}
	f.created = ak
	return &iam.CreateAccessKeyOutput{AccessKey: ak}, nil
}
func (f *fakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	f.deleted = append(f.deleted, aws.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

type fakeSTS struct {
	failN int
	calls int
}

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.calls++
	if f.calls <= f.failN {
		return nil, errors.New("InvalidClientTokenId (eventual consistency)")
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
}

func adminJSON() []byte {
	b, _ := json.Marshal(awsCreds{AccessKeyID: "AKIAADMIN", SecretAccessKey: "adminsecret"})
	return b
}

func newTestRotator(iamFake *fakeIAM, stsFake *fakeSTS) *awsIAMRotator {
	r := &awsIAMRotator{vault: staticVault{val: adminJSON()}}
	r.newIAM = func(string, awsCreds) iamAPI { return iamFake }
	r.newSTS = func(string, awsCreds) stsAPI { return stsFake }
	r.verifyRetries = 3
	r.verifyDelay = 0
	return r
}

func cfg() map[string]any {
	return map[string]any{"target_user": "svc-rotated", "admin_secret_id": "sec-admin", "region": "us-east-1"}
}

func TestAWSIAM_MintCreatesAndReturnsJSON(t *testing.T) {
	f := &fakeIAM{}
	r := newTestRotator(f, &fakeSTS{})
	val, err := r.Mint(context.Background(), cfg())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	var got awsCreds
	if err := json.Unmarshal(val, &got); err != nil {
		t.Fatalf("Mint returned non-JSON: %v", err)
	}
	if got.AccessKeyID != "AKIANEW" || got.SecretAccessKey != "newsecret" {
		t.Errorf("minted creds = %+v, want the newly created key", got)
	}
}

func TestAWSIAM_MintDeletesOldestWhenTwoKeys(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour)
	newer := time.Now().Add(-1 * time.Hour)
	f := &fakeIAM{keys: []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("AKIAOLD"), CreateDate: &old},
		{AccessKeyId: aws.String("AKIANEWER"), CreateDate: &newer},
	}}
	r := newTestRotator(f, &fakeSTS{})
	if _, err := r.Mint(context.Background(), cfg()); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "AKIAOLD" {
		t.Errorf("deleted = %v, want [AKIAOLD] (oldest, to make room)", f.deleted)
	}
}

func TestAWSIAM_VerifyRetriesThenSucceeds(t *testing.T) {
	s := &fakeSTS{failN: 2}
	r := newTestRotator(&fakeIAM{}, s)
	val, _ := json.Marshal(awsCreds{AccessKeyID: "AKIANEW", SecretAccessKey: "newsecret"})
	if err := r.Verify(context.Background(), cfg(), val); err != nil {
		t.Fatalf("Verify should succeed after retries: %v", err)
	}
	if s.calls != 3 {
		t.Errorf("STS calls = %d, want 3 (2 failures + 1 success)", s.calls)
	}
}

func TestAWSIAM_CleanupDeletesAllButNewest(t *testing.T) {
	oldest := time.Now().Add(-72 * time.Hour)
	newest := time.Now().Add(-1 * time.Hour)
	f := &fakeIAM{keys: []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("AKIAOLD"), CreateDate: &oldest},
		{AccessKeyId: aws.String("AKIALIVE"), CreateDate: &newest},
	}}
	r := newTestRotator(f, &fakeSTS{})
	if err := r.Cleanup(context.Background(), cfg()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "AKIAOLD" {
		t.Errorf("deleted = %v, want [AKIAOLD] (all but newest)", f.deleted)
	}
}

func TestAWSIAM_VerifyFailsAfterAllRetries(t *testing.T) {
	s := &fakeSTS{failN: 100} // always fails
	r := newTestRotator(&fakeIAM{}, s)
	val, _ := json.Marshal(awsCreds{AccessKeyID: "AKIANEW", SecretAccessKey: "newsecret"})
	if err := r.Verify(context.Background(), cfg(), val); err == nil {
		t.Fatal("Verify should fail when all attempts fail")
	}
	if s.calls != 3 {
		t.Errorf("STS calls = %d, want 3 (verifyRetries)", s.calls)
	}
}

func TestAWSIAM_ValidateConfig(t *testing.T) {
	r := &awsIAMRotator{}
	if err := r.ValidateConfig(map[string]any{"admin_secret_id": "s"}); err == nil {
		t.Error("want error when target_user missing")
	}
	if err := r.ValidateConfig(map[string]any{"target_user": "u"}); err == nil {
		t.Error("want error when admin_secret_id missing")
	}
	if err := r.ValidateConfig(cfg()); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}
