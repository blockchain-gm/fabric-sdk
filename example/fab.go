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
	fabConfig, err := libfab.LoadConfig("./")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	caConfig, err := libca.LoadDBConfig("./")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ca, err := libca.NewCaClient("ca-org1", caConfig)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	orgEnv, err := fabConfig.GetEnvCache()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// return

	signer, err := orgEnv.LoadCrypto("root", ca)
	if err != nil {
		fmt.Println("LoadCrypto err", err.Error())
		return
	}
	_ = signer

	// return
	proposal, txID, err := libfab.CreateProposal(
		signer,
		fabConfig.Channel,
		fabConfig.Chaincode,
		"putstandard", "key", "value",
	)
	if err != nil {
		fmt.Println("CreateProposal err", err.Error())
		return
	}

	fmt.Println("TxID:", txID)
	// assember := &Assembler{Signer: crypto}
	// return

	signedProp, err := libfab.SignProposal(proposal, signer)
	if err != nil {
		fmt.Println(err.Error())
		return
		// panic(err)
	}

	endorser, err := libfab.CreateEndorserClient(fabConfig.PeerAddr, signer.TLSCACerts)
	if err != nil {
		fmt.Println(err.Error())
		return
		// panic(err)
	}

	response, err := endorser.ProcessProposal(context.Background(), signedProp)
	if err != nil {
		fmt.Printf("Err processing proposal: %v\n", err)
		return
	}
	if response.Response.Status < 200 || response.Response.Status >= 400 {
		fmt.Printf("Err processing proposal status: %d\n", response.Response.Status)
		return
	}

	envelope, err := libfab.CreateSignedTx(proposal, signer, response)
	if err != nil {
		fmt.Println(err.Error())
		return
		// panic(err)
	}

	broadcaster, err := libfab.CreateBroadcaster(fabConfig.OrdererAddr, signer)
	if err != nil {
		fmt.Println(err.Error())
		return
		// panic(err)
	}

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

	watchBlock, err := libfab.CreateWatchServer(fabConfig.PeerAddr, fabConfig.Channel, signer)
	if err != nil {
		fmt.Printf("CreateWatchServer err: %s\n", err)
		return
	}

	start := time.Now()
	go watchBlock.Start(start)
	watchBlock.Wait()

}
