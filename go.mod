module fabric-sdk

go 1.13

require (
	github.com/Knetic/govaluate v3.0.0+incompatible // indirect
	github.com/Shopify/sarama v1.26.1 // indirect
	github.com/cloudflare/cfssl v1.4.1
	github.com/fsouza/go-dockerclient v1.6.4 // indirect
	github.com/golang/protobuf v1.4.0
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hyperledger/fabric v1.4.3
	github.com/hyperledger/fabric-amcl v0.0.0-20200128223036-d1aa2665426a // indirect
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.2.2
	github.com/onsi/ginkgo v1.12.0 // indirect
	github.com/onsi/gomega v1.9.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/spf13/viper v1.6.3 // indirect
	github.com/sykesm/zap-logfmt v0.0.3 // indirect
	// github.com/tjfoc/gmsm v1.3.0
	github.com/tjfoc/gmsm v1.2.3
	github.com/tjfoc/gmtls v1.2.1 // indirect
	go.uber.org/zap v1.14.1
	golang.org/x/crypto v0.0.0-20200414173820-0848c9571904
	google.golang.org/grpc v1.28.1 // indirect
)

replace github.com/hyperledger/fabric v1.4.3 => github.com/blockchain-gm/fabric v0.0.0-20200423071858-46723fbca0a9

replace github.com/tjfoc/gmsm v1.2.3 => github.com/blockchain-gm/gmsm v0.0.0-20200423074409-6ddd939b0ea7

replace github.com/tjfoc/gmtls v1.2.1 => github.com/blockchain-gm/gmtls v0.0.0-20200423074652-5e39cd9262b9
