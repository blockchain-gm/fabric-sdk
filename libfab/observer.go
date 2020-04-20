package libfab

import (
	"fmt"
	"time"

	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/peer"
)

type Observer struct {
	d peer.Deliver_DeliverFilteredClient

	signal chan error
}

func CreateObserver(addr, channel string, crypto *Crypto) *Observer {
	var (
		seek *common.Envelope
		err  error
	)

	deliverer, err := CreateDeliverFilteredClient(addr, crypto.TLSCACerts)
	if err != nil {
		panic(err)
	}

	seek, err = CreateSignedDeliverNewestEnv(channel, crypto)
	if err != nil {
		panic(err)
	}

	if err = deliverer.Send(seek); err != nil {
		panic(err)
	}

	// drain first response
	if _, err = deliverer.Recv(); err != nil {
		panic(err)
	}

	return &Observer{d: deliverer, signal: make(chan error, 10)}
}

func (o *Observer) Start(now time.Time) {
	defer close(o.signal)

	n := 0
	for {
		r, err := o.d.Recv()
		if err != nil {
			o.signal <- err
		}

		fb := r.Type.(*peer.DeliverResponse_FilteredBlock)
		n = n + len(fb.FilteredBlock.FilteredTransactions)
		// fmt.Printf("Time %v\tBlock %d\tTx %d\n", time.Since(now), fb.FilteredBlock.Number, len(fb.FilteredBlock.FilteredTransactions))
		fmt.Printf("Block %d\n", fb.FilteredBlock.Number)
		for i := 0; i < len(fb.FilteredBlock.FilteredTransactions); i++ {
			fmt.Printf("%d\tTx:%s\n", i+1, fb.FilteredBlock.FilteredTransactions[i].GetTxid())
			fmt.Printf("TxType:%d\t TxValidationCode:%d\n",
				fb.FilteredBlock.FilteredTransactions[i].GetType(),
				fb.FilteredBlock.FilteredTransactions[i].GetTxValidationCode())
			fmt.Printf("Data:%v\n", fb.FilteredBlock.FilteredTransactions[i].GetData())
		}
	}
}

func (o *Observer) Wait() {
	for err := range o.signal {
		if err != nil {
			fmt.Printf("Observed error: %s\n", err)
		}
	}
}
