// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
)

// ecPointToProtobuf converts crypto.ECPoint to common.ECPoint (protobuf message)
// This will work once the protobuf files are regenerated with ECPoint definition
func ecPointToProtobuf(p *crypto.ECPoint) *common.ECPoint {
	if p == nil {
		return nil
	}
	return &common.ECPoint{
		X: p.X().Bytes(),
		Y: p.Y().Bytes(),
	}
}

// populateOneRoundData populates the OneRoundData in SignatureData from temp data
// This should be called when exiting one-round mode (after round 8 in v2)
func populateOneRoundData(data *common.SignatureData, temp *localTempData) {
	if temp.m != nil {
		// Not in one-round mode
		return
	}

	// Create OneRoundData (will be properly typed after protobuf regeneration)
	oneRoundData := &common.SignatureData_OneRoundData{
		T:        temp.oneRoundT,
		KI:       temp.oneRoundKI,
		RSigmaI:  temp.oneRoundRSigmaI,
		BigR:     ecPointToProtobuf(temp.oneRoundBigR),
		BigRBarJ: make(map[string]*common.ECPoint),
		BigSJ:    make(map[string]*common.ECPoint),
	}

	// Convert BigRBarJ map
	for k, v := range temp.oneRoundBigRBarJ {
		oneRoundData.BigRBarJ[k] = ecPointToProtobuf(v)
	}

	// Convert BigSJ map
	for k, v := range temp.oneRoundBigSJ {
		oneRoundData.BigSJ[k] = ecPointToProtobuf(v)
	}

	data.OneRoundData = oneRoundData
}
