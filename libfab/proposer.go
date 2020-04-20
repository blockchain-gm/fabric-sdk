package libfab

import "github.com/hyperledger/fabric/protos/orderer"

type Broadcaster struct {
	C orderer.AtomicBroadcast_BroadcastClient
}

func CreateBroadcaster(addr string, crypto *Crypto) *Broadcaster {
	client, err := CreateBroadcastClient(addr, crypto.TLSCACerts)
	if err != nil {
		panic(err)
	}

	return &Broadcaster{C: client}
}
