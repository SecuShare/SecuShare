package service

import (
	"testing"

	"github.com/bytemare/opaque"
)

func TestAuthService_ContextMismatch_RegistrationPassLoginFail(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	email := "ctx@example.com"
	password := "Passw0rd!"

	// Client with non-default context while server uses default context.
	conf := opaque.DefaultConfiguration()
	conf.Context = []byte("serenity")
	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	ke1 := client.RegistrationInit([]byte(password))
	regRespBytes, err := svc.RegisterInit(email, ke1.Serialize())
	if err != nil {
		t.Fatalf("RegisterInit: %v", err)
	}
	regResp, err := client.Deserialize.RegistrationResponse(regRespBytes)
	if err != nil {
		t.Fatalf("deserialize registration response: %v", err)
	}
	record, _ := client.RegistrationFinalize(regResp, opaque.ClientRegistrationFinalizeOptions{})
	_, _, err = svc.RegisterFinish(email, record.Serialize())
	if err != nil {
		t.Fatalf("RegisterFinish: %v", err)
	}

	// Login with same client context.
	lke1 := client.LoginInit([]byte(password))
	loginID, ke2Bytes, err := svc.LoginInit(email, lke1.Serialize())
	if err != nil {
		t.Fatalf("LoginInit: %v", err)
	}
	ke2, err := client.Deserialize.KE2(ke2Bytes)
	if err != nil {
		t.Fatalf("deserialize KE2: %v", err)
	}
	ke3, _, err := client.LoginFinish(ke2, opaque.ClientLoginFinishOptions{})
	if err == nil && ke3 != nil {
		_, _, finishErr := svc.LoginFinish(loginID, ke3.Serialize())
		if finishErr == nil {
			t.Fatal("expected login failure under context mismatch")
		}
	}
}
