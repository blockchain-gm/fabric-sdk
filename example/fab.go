package main

import (
	"context"
	"fabric-sdk/libca"
	"fabric-sdk/libfab"
	"fmt"
	"io"
	"time"

	"github.com/hyperledger/fabric/protos/common"
)

func main() {
	config, err := libfab.LoadConfig("./")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ca, err := libca.NewCaClient()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	orgEnv, err := config.GetEnvCache()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	signer, err := orgEnv.LoadCrypto("SBOMYARTTB", ca)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	_ = signer

	proposal, txID := libfab.CreateProposal(
		signer,
		config.Channel,
		"standard",
		"putstandard", "key", "value",
	)
	fmt.Println("TxID:", txID)
	// assember := &Assembler{Signer: crypto}

	signedProp, err := libfab.SignProposal(proposal, signer)
	if err != nil {
		fmt.Println(err.Error())
		return
		// panic(err)
	}

	endorser, err := libfab.CreateEndorserClient(config.PeerAddr, signer.TLSCACerts)
	if err != nil {
		fmt.Println(err.Error())
		return
		// panic(err)
	}

	response, err := endorser.ProcessProposal(context.Background(), signedProp)
	if err != nil || response.Response.Status < 200 || response.Response.Status >= 400 {
		fmt.Printf("Err processing proposal: %v, status: %d\n", err, response.Response.Status)
		return
	}

	envelope, err := libfab.CreateSignedTx(proposal, signer, response)
	if err != nil {
		fmt.Println(err.Error())
		return
		// panic(err)
	}

	broadcaster := libfab.CreateBroadcaster(config.OrdererAddr, signer)
	go func() {
		for {
			res, err := broadcaster.C.Recv()
			if err != nil {
				if err == io.EOF {
					return
				}

				fmt.Printf("Recv broadcast err: %s, status: %+v\n", err, res)
				panic("bcast recv err")
			}

			if res.Status != common.Status_SUCCESS {
				fmt.Printf("Recv errouneous status: %s\n", res.Status)
				panic("bcast recv err")
			}

		}
	}()

	err = broadcaster.C.Send(envelope)
	if err != nil {
		fmt.Printf("Failed to broadcast env: %s\n", err)
		return
	}

	observer := libfab.CreateObserver(config.PeerAddr, config.Channel, signer)
	start := time.Now()
	go observer.Start(start)
	observer.Wait()

}
