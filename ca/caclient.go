package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fabric-sdk/bccsp"
	"fabric-sdk/fabric-ca/api"
	"fabric-sdk/kv"
	"fabric-sdk/msp"
	"fmt"

	"github.com/pkg/errors"
)

type CAClientImpl struct {
	orgName         string
	caName          string
	orgMSPID        string
	cryptoSuite     bccsp.BCCSP
	identityManager *msp.IdentityManager
	userStore       kv.UserStore
	adapter         *fabricCAAdapter
	registrar       EnrollCredentials
	provider        *msp.ProviderFactory
}

// NewCAClient creates a new CA CAClient instance
func NewCAClient(orgName string, mspID string, caName string, stateStorePath string, Registrar *EnrollCredentials, caConfig *api.FabConfig) (*CAClientImpl, error) {
	var (
		caConf api.CaConfig
		ok     bool
	)

	if orgName == "" {
		return nil, errors.New("organization is missing")
	}

	cryptoSuite, err := GetSuiteByConfig(caConfig.SecType)
	if err != nil {
		return nil, err
	}

	if caConf, ok = caConfig.Ca[caName]; !ok {
		return nil, errors.New("ca config not exist")
	}

	config, err := GetCAConfig(&caConf)
	if err != nil {
		return nil, err
	}

	adapter, err := newFabricCAAdapter(caName, cryptoSuite, caConfig.SecType, config)
	if err != nil {
		return nil, errors.Wrapf(err, "error initializing CA [%s]", caName)
	}

	provider := msp.NewProviderFactory()
	userStore, err := provider.CreateUserStore(stateStorePath)
	if err != nil {
		return nil, err
	}

	currentDir, err := getCurrentDirectory()
	if err != nil {
		return nil, err
	}

	// identityManager, err := msp.NewIdentityManager(orgName, mspID, nil, "keys", userStore, cryptoSuite, currentDir)
	identityManager, err := msp.NewIdentityManager(orgName, mspID, nil,
		caConf.KeyStorePath, userStore, cryptoSuite, caConfig.SecType, currentDir)
	if err != nil {
		return nil, fmt.Errorf("identity manager not found for organization '%s", orgName)
	}

	mgr := &CAClientImpl{
		orgName:         orgName,
		caName:          caName,
		orgMSPID:        mspID,
		cryptoSuite:     cryptoSuite,
		identityManager: identityManager,
		userStore:       userStore,
		adapter:         adapter,
		registrar:       *Registrar,
		provider:        provider,
	}
	return mgr, nil
}

func (c *CAClientImpl) GetSigningIdentity(id string) (*msp.User, error) {
	if id == "" {
		return nil, msp.ErrUserNotFound
	}

	registrar, err := c.identityManager.GetSigningIdentity(id)
	if err != nil {
		return nil, err
	}
	return registrar, nil
}

func (c *CAClientImpl) GetUserCertificate(id string) (*x509.Certificate, []byte, error) {
	if id == "" {
		return nil, nil, msp.ErrUserNotFound
	}

	registrar, err := c.identityManager.GetSigningIdentity(id)
	if err != nil {
		return nil, nil, err
	}

	certBytes := registrar.EnrollmentCertificate()
	if certBytes != nil {
		decoded, _ := pem.Decode(certBytes)
		if decoded == nil {
			return nil, nil, errors.New("Failed cert decoding")
		}

		cert, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse certificate: %s", err)
		}

		return cert, certBytes, nil
	}
	return nil, nil, nil
}

func (c *CAClientImpl) GetUserPriKey(id string) ([]byte, string, error) {
	priKey, ski, err := c.identityManager.GetUserPriKey(id)
	if err != nil {
		return nil, ski, err
	}
	return priKey, ski, nil
}

func (c *CAClientImpl) GetUserKeys(id string) ([]byte, []byte, error) {
	priKey, user, err := c.identityManager.GetUserKeys(id)
	if err != nil {
		return nil, nil, err
	}
	return priKey, user.EnrollmentCertificate(), nil
}

//Verify
func (c *CAClientImpl) Verify(id string, msg []byte, sig []byte, hashFamily string) error {
	if id == "" {
		return msp.ErrUserNotFound
	}

	registrar, err := c.identityManager.GetSigningIdentity(id)
	if err != nil {
		return err
	}

	hashOpt, err := bccsp.GetHashOpt(hashFamily)
	if err != nil {
		return fmt.Errorf("failed getting hash function options, %s", err.Error())
	}

	digest, err := c.cryptoSuite.Hash(msg, hashOpt)
	if err != nil {
		return fmt.Errorf("failed computing digest, %s", err.Error())
	}

	valid, err := c.cryptoSuite.Verify(registrar.PrivateKey(), sig, digest, nil)
	if err != nil {
		return fmt.Errorf("could not determine the validity of the signature, %s", err.Error())
	} else if !valid {
		return errors.New("The signature is invalid")
	}
	return nil
}

func (c *CAClientImpl) Sign(id string, msg []byte, hashFamily string) ([]byte, error) {
	if id == "" {
		return nil, msp.ErrUserNotFound
	}

	registrar, err := c.identityManager.GetSigningIdentity(id)
	if err != nil {
		return nil, err
	}

	hashOpt, err := bccsp.GetHashOpt(hashFamily)
	if err != nil {
		return nil, fmt.Errorf("failed getting hash function options, %s", err.Error())
	}
	digest, err := c.cryptoSuite.Hash(msg, hashOpt)
	if err != nil {
		return nil, fmt.Errorf("failed computing digest, %s", err.Error())
	}
	// fmt.Printf("Sign: digest: %X \n", digest)

	// Sign
	// signature, err := c.cryptoSuite.Sign(registrar.PrivateKey(), digest, nil)
	// if err != nil {
	// 	return nil, err
	// }

	// return base64.StdEncoding.EncodeToString(signature), nil
	return c.cryptoSuite.Sign(registrar.PrivateKey(), digest, nil)
}

func (c *CAClientImpl) Enroll(request *api.EnrollmentRequest) error {

	if c.adapter == nil {
		return fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}
	if request.Name == "" {
		return errors.New("enrollmentID is required")
	}
	if request.Secret == "" {
		return errors.New("enrollmentSecret is required")
	}
	// TODO add attributes
	cert, err := c.adapter.Enroll(request)
	if err != nil {
		return errors.Wrap(err, "enroll failed")
	}
	userData := &kv.UserData{
		MSPID:                 c.orgMSPID,
		ID:                    request.Name,
		EnrollmentCertificate: cert,
	}
	err = c.userStore.Store(userData)
	if err != nil {
		return errors.Wrap(err, "enroll failed")
	}
	return nil
}

func (c *CAClientImpl) CreateIdentity(request *api.IdentityRequest) (*api.IdentityResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	if request == nil {
		return nil, errors.New("must provide identity request")
	}

	// Checke required parameters (ID and affiliation)
	if request.ID == "" || request.Affiliation == "" {
		return nil, errors.New("ID and affiliation are required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.CreateIdentity(registrar.PrivateKey(), registrar.EnrollmentCertificate(), request)
}

func (c *CAClientImpl) ModifyIdentity(request *api.IdentityRequest) (*api.IdentityResponse, error) {

	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	if request == nil {
		return nil, errors.New("must provide identity request")
	}

	// Checke required parameters (ID and affiliation)
	if request.ID == "" || request.Affiliation == "" {
		return nil, errors.New("ID and affiliation are required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.ModifyIdentity(registrar.PrivateKey(), registrar.EnrollmentCertificate(), request)
}

func (c *CAClientImpl) RemoveIdentity(request *api.RemoveIdentityRequest) (*api.IdentityResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	if request == nil {
		return nil, errors.New("must provide remove identity request")
	}

	// Checke required parameters (ID)
	if request.ID == "" {
		return nil, errors.New("ID is required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.RemoveIdentity(registrar.PrivateKey(), registrar.EnrollmentCertificate(), request)
}

func (c *CAClientImpl) GetIdentity(id, caname string) (*api.IdentityResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	// Checke required parameters (ID and affiliation)
	if id == "" {
		return nil, errors.New("id is required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.GetIdentity(registrar.PrivateKey(), registrar.EnrollmentCertificate(), id, caname)
}

func (c *CAClientImpl) GetAllIdentities(caname string) ([]*api.IdentityResponse, error) {

	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.GetAllIdentities(registrar.PrivateKey(), registrar.EnrollmentCertificate(), caname)
}

func (c *CAClientImpl) Reenroll(request *api.ReenrollmentRequest) error {

	if c.adapter == nil {
		return fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}
	if request.Name == "" {
		return errors.New("user name missing")
	}

	user, err := c.identityManager.GetSigningIdentity(request.Name)
	if err != nil {
		return errors.Wrapf(err, "failed to retrieve user: %s", request.Name)
	}

	cert, err := c.adapter.Reenroll(user.PrivateKey(), user.EnrollmentCertificate(), request)
	if err != nil {
		return errors.Wrap(err, "reenroll failed")
	}
	userData := &kv.UserData{
		MSPID:                 c.orgMSPID,
		ID:                    user.Identifier().ID,
		EnrollmentCertificate: cert,
	}
	err = c.userStore.Store(userData)
	if err != nil {
		return errors.Wrap(err, "reenroll failed")
	}

	return nil
}

func (c *CAClientImpl) Register(request *api.RegistrationRequest) (string, error) {
	if c.adapter == nil {
		return "", fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}
	if c.registrar.EnrollID == "" {
		return "", api.ErrCARegistrarNotFound
	}
	// Validate registration request
	if request == nil {
		return "", errors.New("registration request is required")
	}
	if request.Name == "" {
		return "", errors.New("request.Name is required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return "", err
	}

	secret, err := c.adapter.Register(registrar.PrivateKey(), registrar.EnrollmentCertificate(), request)
	if err != nil {
		return "", errors.Wrap(err, "failed to register user")
	}

	return secret, nil
}

func (c *CAClientImpl) Revoke(request *RevocationRequest) (*api.RevocationResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}
	if c.registrar.EnrollID == "" {
		return nil, api.ErrCARegistrarNotFound
	}
	// Validate revocation request
	if request == nil {
		return nil, errors.New("revocation request is required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	resp, err := c.adapter.Revoke(registrar.PrivateKey(), registrar.EnrollmentCertificate(), request)
	if err != nil {
		return nil, errors.Wrap(err, "failed to revoke")
	}
	return resp, nil
}

func (c *CAClientImpl) GetCAInfo() (*api.GetCAInfoResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	return c.adapter.GetCAInfo(c.caName)
}

func (c *CAClientImpl) GetAffiliation(affiliation, caname string) (*api.AffiliationResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	// Checke required parameters (affiliation)
	if affiliation == "" {
		return nil, errors.New("affiliation is required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.GetAffiliation(registrar.PrivateKey(), registrar.EnrollmentCertificate(), affiliation, caname)
}

// GetAllAffiliations returns all affiliations that the caller is authorized to see
func (c *CAClientImpl) GetAllAffiliations(caname string) (*api.AffiliationResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization %s", c.orgName)
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.GetAllAffiliations(registrar.PrivateKey(), registrar.EnrollmentCertificate(), caname)
}

func (c *CAClientImpl) AddAffiliation(request *api.AffiliationRequest) (*api.AffiliationResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	if request == nil {
		return nil, errors.New("must provide affiliation request")
	}

	// Checke required parameters (Name)
	if request.Name == "" {
		return nil, errors.New("Name is required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.AddAffiliation(registrar.PrivateKey(), registrar.EnrollmentCertificate(), request)
}

func (c *CAClientImpl) ModifyAffiliation(request *api.ModifyAffiliationRequest) (*api.AffiliationResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	if request == nil {
		return nil, errors.New("must provide affiliation request")
	}

	// Checke required parameters (Name and NewName)
	if request.Name == "" || request.NewName == "" {
		return nil, errors.New("Name and NewName are required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.ModifyAffiliation(registrar.PrivateKey(), registrar.EnrollmentCertificate(), request)
}

func (c *CAClientImpl) RemoveAffiliation(request *api.AffiliationRequest) (*api.AffiliationResponse, error) {
	if c.adapter == nil {
		return nil, fmt.Errorf("no CAs configured for organization: %s", c.orgName)
	}

	if request == nil {
		return nil, errors.New("must provide remove affiliation request")
	}

	// Checke required parameters (Name)
	if request.Name == "" {
		return nil, errors.New("Name is required")
	}

	registrar, err := c.getRegistrar(c.registrar.EnrollID, c.registrar.EnrollSecret)
	if err != nil {
		return nil, err
	}

	return c.adapter.RemoveAffiliation(registrar.PrivateKey(), registrar.EnrollmentCertificate(), request)
}

func (c *CAClientImpl) getRegistrar(enrollID string, enrollSecret string) (*msp.User, error) {
	if enrollID == "" {
		return nil, api.ErrCARegistrarNotFound
	}

	registrar, err := c.identityManager.GetSigningIdentity(enrollID)
	if err != nil {
		if err != msp.ErrUserNotFound {
			return nil, err
		}
		if enrollSecret == "" {
			return nil, api.ErrCARegistrarNotFound
		}

		// Attempt to enroll the registrar
		err = c.Enroll(&api.EnrollmentRequest{Name: enrollID, Secret: enrollSecret})
		if err != nil {
			return nil, err
		}
		registrar, err = c.identityManager.GetSigningIdentity(enrollID)
		if err != nil {
			return nil, err
		}
	}
	return registrar, nil
}
