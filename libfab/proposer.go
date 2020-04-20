package libfab

import "github.com/hyperledger/fabric/protos/orderer"

type Broadcaster struct {
	C orderer.AtomicBroadcast_BroadcastClient
}

func CreateBroadcaster(addr string, crypto *Crypto) (*Broadcaster, error) {
	client, err := CreateBroadcastClient(addr, crypto.TLSCACerts)
	if err != nil {
		return nil, err
	}

	return &Broadcaster{C: client}, nil
}
