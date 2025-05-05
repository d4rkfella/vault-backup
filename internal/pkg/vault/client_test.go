package vault

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockTokenAPI struct {
	mock.Mock
}

func (m *mockTokenAPI) RevokeSelfWithContext(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

type mockAuthAPI struct {
	mock.Mock
	mockToken TokenAPI // Embed mock token API
}

func (m *mockAuthAPI) Token() TokenAPI {
	if m.mockToken == nil {
		m.mockToken = new(mockTokenAPI)
	}
	return m.mockToken
}

type mockSysAPI struct {
	mock.Mock
}

func (m *mockSysAPI) RaftSnapshotWithContext(ctx context.Context, w io.Writer) error {
	args := m.Called(ctx, w)
	return args.Error(0)
}

func (m *mockSysAPI) RaftSnapshotRestoreWithContext(ctx context.Context, r io.Reader, force bool) error {
	args := m.Called(ctx, r, force)
	return args.Error(0)
}

type mockVaultAPI struct {
	mock.Mock
	mockSys  SysAPI
	mockAuth AuthAPI
}

func (m *mockVaultAPI) Sys() SysAPI {
	if m.mockSys == nil {
		m.mockSys = new(mockSysAPI)
	}
	return m.mockSys
}

func (m *mockVaultAPI) Auth() AuthAPI {
	if m.mockAuth == nil {
		m.mockAuth = new(mockAuthAPI)
	}
	return m.mockAuth
}

func (m *mockVaultAPI) SetNamespace(namespace string) {
	m.Called(namespace)
}

func (m *mockVaultAPI) Token() string {
	args := m.Called()
	return args.String(0)
}

var _ TokenAPI = (*mockTokenAPI)(nil)
var _ AuthAPI = (*mockAuthAPI)(nil)
var _ SysAPI = (*mockSysAPI)(nil)
var _ VaultAPI = (*mockVaultAPI)(nil)

func getMockVaultAPIs(api VaultAPI) (*mockVaultAPI, *mockSysAPI, *mockAuthAPI, *mockTokenAPI) {
	mVault := api.(*mockVaultAPI)
	mSys := mVault.Sys().(*mockSysAPI)
	mAuth := mVault.Auth().(*mockAuthAPI)
	mToken := mAuth.Token().(*mockTokenAPI)
	return mVault, mSys, mAuth, mToken
}

func TestNewClient_NilConfig(t *testing.T) {
	ctx := context.Background()
	client, err := NewClient(ctx, nil) // Call real constructor
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.ErrorContains(t, err, "config cannot be nil")
}

func TestBackup_Success(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockVaultAPI)
	_, mSys, _, _ := getMockVaultAPIs(mockAPI)

	client := &Client{
		vaultClient: mockAPI,
	}
	var buf bytes.Buffer
	const expectedData = "mock snapshot data"

	mSys.On("RaftSnapshotWithContext", ctx, &buf).Return(nil).Once().Run(func(args mock.Arguments) {
		writer := args.Get(1).(io.Writer)
		_, _ = writer.Write([]byte(expectedData))
	})

	err := client.Backup(ctx, &buf)

	require.NoError(t, err)
	assert.Equal(t, expectedData, buf.String(), "Expected snapshot data in buffer")
	mSys.AssertExpectations(t)
}

func TestBackup_Failure(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockVaultAPI)
	_, mSys, _, _ := getMockVaultAPIs(mockAPI)

	client := &Client{
		vaultClient: mockAPI,
	}
	var buf bytes.Buffer
	expectedError := errors.New("raft snapshot failed")

	mSys.On("RaftSnapshotWithContext", ctx, &buf).Return(expectedError).Once()

	err := client.Backup(ctx, &buf)

	require.Error(t, err)
	assert.EqualError(t, err, expectedError.Error())
	assert.Empty(t, buf.String(), "Buffer should be empty on failure")
	mSys.AssertExpectations(t)
}

func TestRestore_Success(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockVaultAPI)
	_, mSys, _, _ := getMockVaultAPIs(mockAPI)
	forceRestore := false

	client := &Client{
		vaultClient:  mockAPI,
		forceRestore: forceRestore,
	}
	reader := strings.NewReader("test-restore-data")

	mSys.On("RaftSnapshotRestoreWithContext", ctx, mock.AnythingOfType("*strings.Reader"), forceRestore).Return(nil).Once()

	err := client.Restore(ctx, reader)

	require.NoError(t, err)
	mSys.AssertExpectations(t)
}

func TestRestore_Success_Force(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockVaultAPI)
	_, mSys, _, _ := getMockVaultAPIs(mockAPI)
	forceRestore := true

	client := &Client{
		vaultClient:  mockAPI,
		forceRestore: forceRestore,
	}
	reader := strings.NewReader("test-restore-data-force")

	mSys.On("RaftSnapshotRestoreWithContext", ctx, mock.AnythingOfType("*strings.Reader"), forceRestore).Return(nil).Once()

	err := client.Restore(ctx, reader)

	require.NoError(t, err)
	mSys.AssertExpectations(t)
}

func TestRestore_Failure(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockVaultAPI)
	_, mSys, _, _ := getMockVaultAPIs(mockAPI)
	forceRestore := false

	client := &Client{
		vaultClient:  mockAPI,
		forceRestore: forceRestore,
	}
	reader := bytes.NewBufferString("bad-restore-data")
	expectedError := errors.New("raft restore failed")

	mSys.On("RaftSnapshotRestoreWithContext", ctx, mock.AnythingOfType("*bytes.Buffer"), forceRestore).Return(expectedError).Once()

	err := client.Restore(ctx, reader)

	require.Error(t, err)
	assert.EqualError(t, err, expectedError.Error())
	mSys.AssertExpectations(t)
}

func TestRevokeToken_Success(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockVaultAPI)
	mVault, _, _, mToken := getMockVaultAPIs(mockAPI)
	const testToken = "test-client-token"

	client := &Client{
		vaultClient: mockAPI,
	}

	mVault.On("Token").Return(testToken).Once()
	mToken.On("RevokeSelfWithContext", ctx, testToken).Return(nil).Once()

	err := client.RevokeToken(ctx)

	require.NoError(t, err)
	mVault.AssertExpectations(t)
	mToken.AssertExpectations(t)
}

func TestRevokeToken_Failure(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockVaultAPI)
	mVault, _, _, mToken := getMockVaultAPIs(mockAPI)
	const testToken = "test-client-token-fail"
	expectedError := errors.New("token revocation failed")

	client := &Client{
		vaultClient: mockAPI,
	}

	mVault.On("Token").Return(testToken).Once()
	mToken.On("RevokeSelfWithContext", ctx, testToken).Return(expectedError).Once()

	err := client.RevokeToken(ctx)

	require.Error(t, err)
	assert.EqualError(t, err, expectedError.Error())
	mVault.AssertExpectations(t)
	mToken.AssertExpectations(t)
}
