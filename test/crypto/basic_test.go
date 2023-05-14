package crypto

import (
	"finalbruh/pkg/utils"
	"testing"
)

func TestBasicSystem(t *testing.T) {
	utils.SetDebug(true)
	privkey, err := utils.GenerateAsymKey()
	if err != nil {
		t.Errorf("Couldn't Generate asym key")
	}
	sig, err := utils.Sign(privkey, "hello")
	if err != nil {
		t.Errorf("Couldn't Sign with asym key")
	}
	valid := utils.Verify(&privkey.PublicKey, "hello", sig)
	if !valid {
		t.Errorf("Couldn't Verify with asym key")
	}
	ciphertext, err := utils.PubEncrypt(&privkey.PublicKey, "hello")
	if err != nil {
		t.Errorf("Couldn't Encrypt with asym key")
	}
	plaintext, err := utils.PubDecrypt(privkey, ciphertext)
	if err != nil || plaintext != "hello" {
		t.Errorf("Couldn't Decrypt with asym key")
	}
	keyy, gcm, err := utils.GenerateSymKey()
	if err != nil {
		t.Errorf("Couldn't Generate sym key")
	}
	ciphertext = utils.SymEncrypt(gcm, "hi")
	plaintext, err = utils.SymDecrypt(gcm, ciphertext)
	if err != nil || plaintext != "hi" {
		t.Errorf("Couldn't Decrypt with asym key")
	}

	enc, err := utils.EncodePublicKey(&privkey.PublicKey)
	if err != nil {
		t.Errorf("Couldn't Encode pub key")
	}

	_, err = utils.DecodePublicKey(enc)
	if err != nil {
		t.Errorf("Couldn't Decode pub key")
	}

	resy, err := utils.PubEncrypt(&privkey.PublicKey, keyy)
	if err != nil {
		t.Errorf("Couldn't Encrypt key via pub key")
	}

	finny, err := utils.PubDecrypt(privkey, resy)
	if err != nil || finny != keyy {
		t.Errorf("Couldn't Decrypt key via priv key")
	}

	longMSG := "0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789" +
		"0123456789 0123456789 0123456789 0123456789 0123456789"
	resy2, err := utils.PubEncrypt(&privkey.PublicKey, longMSG)
	if err != nil {
		t.Errorf("Couldn't Encrypt key via pub key")
	}

	finny2, err := utils.PubDecrypt(privkey, resy2)
	if err != nil || finny2 != longMSG {
		t.Errorf("Couldn't Decrypt key via priv key")
	}
}
