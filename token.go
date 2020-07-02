package vault

import (
	vault "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"time"
)

const renewBeforeDuration = time.Second * 10

type AuthProvider interface {
	Auth() (*authResponse, error)
}

type TokenAuth struct {
	tokenAuthClient *vault.TokenAuth
	client          *Client
	authProvider    AuthProvider
	expires         time.Time
}

func NewTokenAuth(c *Client, p AuthProvider) *TokenAuth {

	return &TokenAuth{
		tokenAuthClient: c.Auth().Token(),
		client:          c,
		authProvider:    p,
	}
}

func (t *TokenAuth) EnableAutoRenew(errs chan<- error) {
	go func() {
		for {
			renewIn := time.Until(t.expires) - renewBeforeDuration
			// ticker on duration 0 will panic :(
			// this will cause an instant renew
			if renewIn <= 0 {
				renewIn = time.Duration(1)
			}
			ticker := time.NewTicker(renewIn)
			<-ticker.C
			err := t.Renew()
			if err != nil && errs != nil {
				errs <- err // this may block until someone "reads" the error!
			}
		}
	}()
}

func (t *TokenAuth) Auth() error {
	res, err := t.authProvider.Auth()
	if err != nil {
		return err
	}
	t.client.SetToken(res.Auth.ClientToken)
	t.expires = t.calcExpire(res.Auth.LeaseDuration)
	return nil
}

func (t *TokenAuth) Renew() error {
	secret, errRenew := t.tokenAuthClient.RenewSelf(0)
	if errRenew != nil {
		if t.authProvider == nil {
			return errors.WithMessage(errRenew, "token renew failed")
		}
		errAuth := t.Auth()
		if errAuth != nil {
			return errors.Wrapf(errAuth, "creating a new token failed after token renew failed with: %s", errRenew)
		}
		return nil
	}
	t.client.SetToken(secret.Auth.ClientToken)
	t.expires = t.calcExpire(secret.Auth.LeaseDuration)
	return nil
}

func (t *TokenAuth) calcExpire(leaseDuration int) time.Time {
	return time.Now().Add(time.Duration(leaseDuration) * time.Second)
}
