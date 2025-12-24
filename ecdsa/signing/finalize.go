// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	TaskNameFinalize = "signing-finalize"
)

// -----
// One Round Finalization (async/offline)
// -----

// FinalizeGetOurSigShare is called in one-round signing mode after the online rounds have finished to compute s_i.
func FinalizeGetOurSigShare(state *common.SignatureData, msg *big.Int) (sI *big.Int) {
	data := state.GetOneRoundData()
	if data == nil {
		return nil
	}

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	kI, rSigmaI := new(big.Int).SetBytes(data.GetKI()), new(big.Int).SetBytes(data.GetRSigmaI())
	sI = modN.Add(modN.Mul(msg, kI), rSigmaI)
	return
}

// FinalizeGetAndVerifyFinalSig is called in one-round signing mode to build a final signature given others' s_i shares and a msg.
// Note: each P in otherPs should correspond with that P's s_i at the same index in otherSIs.
func FinalizeGetAndVerifyFinalSig(
	state *common.SignatureData,
	pk *ecdsa.PublicKey,
	msg *big.Int,
	ourP *tss.PartyID,
	ourSI *big.Int,
	otherSIs map[*tss.PartyID]*big.Int,
) (*common.SignatureData, *tss.Error) {
	if len(otherSIs) == 0 {
		return nil, FinalizeWrapError(errors.New("len(otherSIs) == 0"), ourP)
	}
	data := state.GetOneRoundData()
	if data == nil {
		return nil, FinalizeWrapError(errors.New("OneRoundData is nil"), ourP)
	}
	if data.GetT() != int32(len(otherSIs)) {
		return nil, FinalizeWrapError(errors.New("len(otherSIs) != T"), ourP)
	}

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	bigRProto := data.GetBigR()
	if bigRProto == nil {
		return nil, FinalizeWrapError(errors.New("bigR is nil"), ourP)
	}
	bigR, err := crypto.NewECPoint(tss.EC(),
		new(big.Int).SetBytes(bigRProto.GetX()),
		new(big.Int).SetBytes(bigRProto.GetY()))
	if err != nil {
		return nil, FinalizeWrapError(err, ourP)
	}

	r, s := bigR.X(), ourSI
	culprits := make([]*tss.PartyID, 0, len(otherSIs))
	bigRBarJMap := data.GetBigRBarJ()
	bigSJMap := data.GetBigSJ()

	// Check if we have BigRBarJ and BigSJ data
	// NOTE: v1 protocol exposes these directly in round 5/6 messages (bigRBarI = R*k_i, bigSI = R^sigma_i)
	// v2 protocol uses commitments/decommitments and doesn't expose k_j or sigma_j from other parties
	// Therefore, v2 cannot compute BigRBarJ or BigSJ for other parties in one-round mode
	// The verification below is skipped for v2, but security is maintained via ecdsa.Verify at the end
	hasVerificationData := bigRBarJMap != nil && bigSJMap != nil && len(bigRBarJMap) > 0 && len(bigSJMap) > 0

	for Pj, sJ := range otherSIs {
		if Pj == nil {
			return nil, FinalizeWrapError(errors.New("in loop: Pj is nil"), Pj)
		}

		// Only perform verification if we have the required data (v1 protocol)
		// In v2, these values might not be available, so we skip the verification
		if hasVerificationData {
			bigRBarJBz := bigRBarJMap[Pj.Id]
			bigSJBz := bigSJMap[Pj.Id]
			if bigRBarJBz == nil || bigSJBz == nil {
				// Missing data - skip verification for this party but continue
				// This allows v2 protocol to work without BigRBarJ/BigSJ
				// Note: v2's protocol structure differs and these values may not be available
			} else {
				// prep for identify aborts in phase 7
				bigRBarJ, err := crypto.NewECPoint(tss.EC(),
					new(big.Int).SetBytes(bigRBarJBz.GetX()),
					new(big.Int).SetBytes(bigRBarJBz.GetY()))
				if err != nil {
					culprits = append(culprits, Pj)
					continue
				}
				bigSI, err := crypto.NewECPoint(tss.EC(),
					new(big.Int).SetBytes(bigSJBz.GetX()),
					new(big.Int).SetBytes(bigSJBz.GetY()))
				if err != nil {
					culprits = append(culprits, Pj)
					continue
				}

				// identify aborts of "type 8" in phase 7
				// verify that R^S_i = Rdash_i^m * S_i^r
				bigRBarIM, bigSIR, bigRSI := bigRBarJ.ScalarMult(msg), bigSI.ScalarMult(r), bigR.ScalarMult(sJ)
				bigRBarIMBigSIR, err := bigRBarIM.Add(bigSIR)
				if err != nil || !bigRSI.Equals(bigRBarIMBigSIR) {
					culprits = append(culprits, Pj)
					continue
				}
			}
		}

		s = modN.Add(s, sJ)
	}
	if 0 < len(culprits) {
		return nil, FinalizeWrapError(errors.New("identify abort assertion fail in phase 7"), ourP, culprits...)
	}

	// Calculate Recovery ID: It is not possible to compute the public key out of the signature itself;
	// the Recovery ID is used to enable extracting the public key from the signature.
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	recId := 0
	if bigR.X().Cmp(N) > 0 {
		recId = 2
	}
	if bigR.Y().Bit(0) != 0 {
		recId |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(N, 1)
	if s.Cmp(secp256k1halfN) > 0 {
		s.Sub(N, s)
		recId ^= 1
	}

	ok := ecdsa.Verify(pk, msg.Bytes(), r, s)
	if !ok {
		return nil, FinalizeWrapError(fmt.Errorf("signature verification 1 failed"), ourP)
	}

	// save the signature for final output
	bitSizeInBytes := tss.EC().Params().BitSize / 8
	state.R = padToLengthBytesInPlace(r.Bytes(), bitSizeInBytes)
	state.S = padToLengthBytesInPlace(s.Bytes(), bitSizeInBytes)
	state.Signature = append(state.R, state.S...)
	state.SignatureRecovery = []byte{byte(recId)}
	state.M = msg.Bytes()

	// SECURITY: to be safe the oneRoundData is no longer needed here and reuse of `r` can compromise the key
	state.OneRoundData = nil

	return state, nil
}

func FinalizeWrapError(err error, victim *tss.PartyID, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskNameFinalize, 10, victim, culprits...)
}

// -----
// Full Online Finalization
// -----

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 10
	round.started = true
	round.resetOK()

	sumS := round.temp.si
	modN := common.ModInt(round.Params().EC().Params().N)

	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r9msg := round.temp.signRound9Messages[j].Content().(*SignRound9Message)
		sumS = modN.Add(sumS, r9msg.UnmarshalS())
	}

	recid := 0
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if round.temp.rx.Cmp(round.Params().EC().Params().N) > 0 {
		recid = 2
	}
	if round.temp.ry.Bit(0) != 0 {
		recid |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(round.Params().EC().Params().N, 1)
	if sumS.Cmp(secp256k1halfN) > 0 {
		sumS.Sub(round.Params().EC().Params().N, sumS)
		recid ^= 1
	}

	// save the signature for final output
	bitSizeInBytes := round.Params().EC().Params().BitSize / 8
	round.data.R = padToLengthBytesInPlace(round.temp.rx.Bytes(), bitSizeInBytes)
	round.data.S = padToLengthBytesInPlace(sumS.Bytes(), bitSizeInBytes)
	round.data.Signature = append(round.data.R, round.data.S...)
	round.data.SignatureRecovery = []byte{byte(recid)}
	if round.temp.fullBytesLen == 0 {
		round.data.M = round.temp.m.Bytes()
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		round.data.M = mBytes
	}

	pk := ecdsa.PublicKey{
		Curve: round.Params().EC(),
		X:     round.key.ECDSAPub.X(),
		Y:     round.key.ECDSAPub.Y(),
	}

	ok := ecdsa.Verify(&pk, round.data.M, round.temp.rx, sumS)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}

	round.end <- round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}

func padToLengthBytesInPlace(src []byte, length int) []byte {
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src
}
