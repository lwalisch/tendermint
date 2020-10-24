package uvm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/tendermint/tendermint/types"
	"gopkg.in/mgo.v2/bson"
)

type PrivValidatorKeyFile struct {
	Address     string      `json:"address"`
	PubkeyJSON  PubkeyJSON  `json:"pub_key"`
	PrivkeyJSON PrivkeyJSON `json:"priv_key"`
}

type PubkeyJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type PrivkeyJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ProposerNonceTxBSON struct {
	Signature TxSignatureBSON `bson:"signature"`
	Nonce     string          `bson:"nonce"`
	Type      string          `bson:"type"`
}

type TxSignatureBSON struct {
	Pubkey string `bson:"pubkey"`
	Sig    string `bson:"sig"`
	SigMsg string `bson:"sig_msg"`
}

type KeyPair struct {
	PubKey  ed25519.PublicKey
	PrivKey ed25519.PrivateKey
}

// ParseKeyFile parses the JSON validator key file from the tendermint config directory. It requires a
// file path to the key file.
func ParseKeyFile(validatorKeyFilePath string) KeyPair {
	var privValidatorJSON PrivValidatorKeyFile

	fmt.Printf("priv validator file path: %v\n", validatorKeyFilePath)
	jsonBytes, _ := ioutil.ReadFile(validatorKeyFilePath)

	_ = json.Unmarshal(jsonBytes, &privValidatorJSON)

	privKeyBytes, _ := base64.StdEncoding.DecodeString(privValidatorJSON.PrivkeyJSON.Value)
	pubKeyBytes, _ := base64.StdEncoding.DecodeString(privValidatorJSON.PubkeyJSON.Value)

	return KeyPair{PrivKey: privKeyBytes, PubKey: pubKeyBytes}
}

// GetProposerNonceTx is used by the BlockExecutor when creating a ProposalBlock to add a special tx
// from the block proposer, which is not reaped from the mempool, but directly added to the txs of
// the proposed block. This tx is utilized for Uncoordinated Validator Management (UVM) to let
// validators agree upon the nonce of a block proposer of the previous block. It returns the bson
// encoded ProposerNonceTx and its size in bytes.
func GetProposerNonceTx(validatorKeyPair *KeyPair) (types.Tx, int64) {

	fmt.Println("Pubkey:", base64.StdEncoding.EncodeToString(validatorKeyPair.PubKey))
	fmt.Println("Privkey:", base64.StdEncoding.EncodeToString(validatorKeyPair.PrivKey))

	sigMsg := make([]byte, 8)
	_, _ = rand.Read(sigMsg)

	signature := ed25519.Sign(validatorKeyPair.PrivKey, sigMsg)

	txSignature := TxSignatureBSON{
		Pubkey: base64.StdEncoding.EncodeToString(validatorKeyPair.PubKey),
		Sig:    base64.StdEncoding.EncodeToString(signature),
		SigMsg: base64.StdEncoding.EncodeToString(sigMsg),
	}

	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)

	proposerNonceTx := ProposerNonceTxBSON{
		Signature: txSignature,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Type:      "proposer_nonce",
	}

	proposerNonceTxBSON, _ := bson.Marshal(&proposerNonceTx)

	txSize := int64(len(proposerNonceTxBSON))

	return proposerNonceTxBSON, txSize
}
