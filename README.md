
# Lambda proofDP

The proofDP package is the [PoC](https://en.wikipedia.org/wiki/Proof_of_concept) implementation of the [proof of data possession](http://cryptowiki.net/index.php?title=Proof_of_data_possession)(aka PDP) algorithm applied by [Lambda project](https://lambda.im/).

**Note**: Lambda project depends on an *altered version* of proofDP for development convenience. But the core mechanism remains the same.

## Workflow

The PDP algorithm implemented by proofDP is based on a three-party-model as illustrated in following figure:

![three-party-model](https://ars.els-cdn.com/content/image/1-s2.0-S0045790613002528-fx1.jpg)

Specifically, the involved parties are:

 1. **User**: the data owner and the service consumer
 2. **Cloud Server**: the storage service provider
 3. **Third party audit**(aka TPA) : the transaction validator
 
In one full round of data possession proof/validation, 6 steps would be excuted respectively by the parties:

### Initialize the math Infrastructure

The math infrastructure is required by **all 3 parties**. In other words, they all need to excute the following code snippet:

```go
// load the parameter from configure file
aParam, e := InitAParam(cfgFile)
if e != nil {
// failure operation
}
// create a pairing structure from the parameter
pairing := GenPairingWithAParam(aParam)
```

In the snippet above, a parameter is loaded from given configure file (`cfgFile`) using `InitAParam()`. And then a [pairing](https://en.wikipedia.org/wiki/Pairing) instance is created from the parameter with `GenPairingWithAParam()`.

**Note**: The configure file is strictly formatted. A sample file is provided in the repository. See [cfg/a.param](https://github.com/LambdaIM/proofDP/blob/master/cfg/a.param) for more details.

### Create user-specific key set

**Users** need to create a unique key set as the cryptographical basis of possession proof/validation.

```go
// generate the key set for proof of data possession
keySet := GenKeySet(rsaPubKey, rsaPriKey, pairing)
```

Currently, `GenKeySet()` applys a pair of [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) keys for TPA-user communication in proof validation procedure.

### Create tag for data

Before outsourcing their data, **users** supposed to calculate tags for later possession proof generation and validation.

```go
// generate the data tag
tag := GenTag(pairing, keySet, sampleData, sampleIndex)
```

Note that `GenTag()` requires `[]byte` form data and data index (used to locate the data position). And `GenChallenge()` also need `[]byte` form data input. 

### Generate challenge for data possession

**TPA**, who knows the basic data infomation (enough to form index), will generate a random challenge to make sure **cloud server** is holding the data.

```go
// generate the challenge for data possession validation
challenge := GenChallenge(pairing, sampleIndex)
```

Technically speaking, the index parameter is not required for `GenChallenge()` create a challenge.

### Create proof against challenge

**Cloud servers** will generate possession proof in response to provided challenges.

```go
// response to the given challenge
proof := GenProof(pairing, publicKey, sampleData, challenge, tag, accumulation)
```

The `accumulation` parameter in `GenProof()` is designed for future extension. And in most cases, the `accumulation` is actually nonfunctional.

### Verify the proof

**TPA** will validate the possession proof with responding challenge.

```go
ok := Verify(pairing, keySet.Pk, sampleIndex, challenge, proof, accumulation)
```

Likewise, the `accumulation` here is reserved for future extension.

## Sample

The `TestProofDPPositive()`/`TestProofDPNegative()`/`TestProofDPFile()` tests act as excutable samples for proofDP usage. Please check [proof_test.go](https://github.com/LambdaIM/proofDP/blob/master/proof_test.go) for details.

## License

Lambda proofDP is under LGPL v3.0 license. See [LICENSE](https://github.com/LambdaIM/proofDP/blob/master/LICENSE) for details.
