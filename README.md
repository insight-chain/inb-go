[JSON RPC server](https://github.com/insight-chain/inb-go/wiki) 

## INB GO

Official golang implementation of the Insight Chain


## Building 

First, you need both a Go (version 1.10 or later) and a C compiler.

```shell
make ginb
```

or, to build the full suite of utilities:

```shell
make all
```


## Running

Going through all the possible command line flags is out of scope here ,
but we've enumerated a few common parameter combos to get you up to speed quickly
on how you can run your own `ginb` instance.

### Full node on the main INB network

By far the most common scenario is people wanting to simply interact with the INB
network: create accounts; transfer funds; Mortgage or release; deploy and interact with contracts. For this
particular use-case the user doesn't care about years-old historical data, so we can
fast-sync quickly to the current state of the network. To do so:

```shell
$ ginb console
```

### Full supernode on the main INB network

If you want to be a supernode and have the right to mine, you have to get someone else's vote in advance and only the 21 nodes with the highest number of votes have the chance.

If you meet the above conditions, please continue.

You need to make your nodeid before you start the network.
```shell
$ ginb nodekey [datadir]
```
The returned nodeid (as enodes.id) needs to be configured in the genesis.json file, as well as your ip, port, name, country and so on.
Data provide some other K-V information if you want to store

```json
{
  "config": {
    "chainId": 891,
    "homesteadBlock": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "vdpos": {
      "period": 3,
      "signerPeriod": 3,
      "signerBlocks": 6,
      "epoch": 201600,
      "maxSignersCount": 21, 
      "minVoterBalance": 1000000000000000000,
      "genesisTimestamp": 1561544470,
      "signers": [
        "0x891b2388ce73356917b21ca54f3039cbdfc29313",
        "0x4643ce2d6d4fe02e2b57070806364dde9eb8cac9",
        "0x230cf5081833c4f16e69e102ea00a4583a33cb11"
      ],
  "enodes":[
            {"address":"0x891b2388ce73356917b21ca54f3039cbdfc29313",
            "id":"327d1a41974ad0a672d9b3dcfada5a934b4c21207e95a40d534bde44c2f7b39c4f10dda7a7bc060c00868a77b522878ab960dff2f23f463616736a1e6e39ea93",
            "ip":"192.168.1.181",
            "port":"30001",
            "name":"inb",
            "nation":"China",
            "city":"beijing",
            "image":"www.image.com",
            "website":"www.insightchain.io",
            "email":"insightchain@xx.com",
            "data":"{\"hobby\":\"money\",\"age\":\"21\"}"},

            {"address":"0x891b2388ce73356917b21ca54f3039cbdfc29313",
            "id":"327d1a41974ad0a672d9b3dcfada5a934b4c21207e95a40d534bde44c2f7b39c4f10dda7a7bc060c00868a77b522878ab960dff2f23f463616736a1e6e39ea93",
            "ip":"192.168.1.181",
            "port":"30001",
            "name":"inb",
            "nation":"China",
            "city":"beijing",
            "image":"www.image.com",
            "website":"www.insightchain.io",
            "email":"insightchain@xx.com",
            "data":"{\"hobby\":\"money\",\"age\":\"21\"}"},

            {"address":"0x891b2388ce73356917b21ca54f3039cbdfc29313",
            "id":"327d1a41974ad0a672d9b3dcfada5a934b4c21207e95a40d534bde44c2f7b39c4f10dda7a7bc060c00868a77b522878ab960dff2f23f463616736a1e6e39ea93",
            "ip":"192.168.1.181",
            "port":"30001",
            "name":"inb",
            "nation":"China",
            "city":"beijing",
            "image":"www.image.com",
            "website":"www.insightchain.io",
            "email":"insightchain@xx.com",
            "data":"{\"hobby\":\"money\",\"age\":\"21\"}"},
]
}
  },
  "coinbase": "0x0000000000000000000000000000000000000000",
  "difficulty": "0x1",
  "extraData": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "gasLimit": "0x2fefd8",
  "nonce": "0x0",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp": "0x00",
  "alloc": {
    "891b2388ce73356917b21ca54f3039cbdfc29313": {
      "balance": "0"
    },
    "4643ce2d6d4fe02e2b57070806364dde9eb8cac9": {
      "balance": "0"
    },
    "230cf5081833c4f16e69e102ea00a4583a33cb11": {
      "balance": "0"
    }
  }
}
```
Vdpos is necessary. Period represents the number of seconds between blocks, signerPeriod represents the number of seconds blocks between two super nodes, signerBlocks represents the number of packaged blocks per super node, epoch represents the interval between emptying voting information and re-voting, and maxSignersCount represents the maximum number of super nodes.
Enodes represents information about all super nodes that were first voted for and everyone automatically connects to the supernodes' networks.

Tip:Then everyone initializes the Genesis Block with the same set of genesis.json files
```shell
$ ginb init path/to/genesis.json
```
Finally start the network
```shell
$ ginb --datadir data1/ --networkid 891 --nodiscover --rpcport 6002 --port 30002 console
```

###  Full node on the INB test network

Transitioning towards developers, if you'd like to play around with creating INB
contracts, you almost certainly would like to do that without any real money involved until
you get the hang of the entire system. In other words, instead of attaching to the main
network, you want to join the **test** network with your node, which is fully equivalent to
the main network, but with play-inber only.

```shell
$ ginb --testnet console
```

The `console` subcommand has the exact same meaning as above and they are equally
useful on the testnet too. Please see above for their explanations if you've skipped here.

Specifying the `--testnet` flag, however, will reconfigure your `ginb` instance a bit:

 * Instead of using the default data directory (`~/.inb` on Linux for example), `ginb`
   will nest itself one level deeper into a `testnet` subfolder (`~/.inb/testnet` on
   Linux). Note, on OSX and Linux this also means that attaching to a running testnet node
   requires the use of a custom endpoint since `ginb attach` will try to attach to a
   production node endpoint by default. E.g.
   `ginb attach <datadir>/testnet/ginb.ipc`. Windows users are not affected by
   this.
 * Instead of connecting the main INB network, the client will connect to the test
   network, which uses different P2P bootnodes, different network IDs and genesis states.
   
*Note: Although there are some internal protective measures to prevent transactions from
crossing over between the main network and test network, you should make sure to always
use separate accounts for play-money and real-money. Unless you manually move
accounts, `ginb` will by default correctly separate the two networks and will not make any
accounts available between them.*


```

### Configuration

As an alternative to passing the numerous flags to the `ginb` binary, you can also pass a
configuration file via:

```shell
$ geinb --config /path/to/your_config.toml
```

To get an idea how the file should look like you can use the `dumpconfig` subcommand to
export your existing configuration:

```shell
$ ginb --your-favourite-flags dumpconfig
```



### Programmatically interfacing `ginb` nodes

As a developer, sooner rather than later you'll want to start interacting with `ginb` and the
Insight network via your own programs and not manually through the console. To aid
this, `ginb` has built-in support for a JSON-RPC based APIs 
and [`ginb` specific APIs]
These can be exposed via HTTP, WebSockets and IPC (UNIX sockets on UNIX based
platforms, and named pipes on Windows).

The IPC interface is enabled by default and exposes all the APIs supported by `ginb`,
whereas the HTTP and WS interfaces need to manually be enabled and only expose a
subset of APIs due to security reasons. These can be turned on/off and configured as
you'd expect.

HTTP based JSON-RPC API options:

  * `--rpc` Enable the HTTP-RPC server
  * `--rpcaddr` HTTP-RPC server listening interface (default: `localhost`)
  * `--rpcport` HTTP-RPC server listening port (default: `8545`)
  * `--rpcapi` API's offered over the HTTP-RPC interface (default: `inb,net,web3`)
  * `--rpccorsdomain` Comma separated list of domains from which to accept cross origin requests (browser enforced)
  * `--ws` Enable the WS-RPC server
  * `--wsaddr` WS-RPC server listening interface (default: `localhost`)
  * `--wsport` WS-RPC server listening port (default: `8546`)
  * `--wsapi` API's offered over the WS-RPC interface (default: `inb,net,web3`)
  * `--wsorigins` Origins from which to accept websockets requests
  * `--ipcdisable` Disable the IPC-RPC server
  * `--ipcapi` API's offered over the IPC-RPC interface (default: `admin,debug,inb.vdpos,miner,net,personal,shh,txpool,web3`)
  * `--ipcpath` Filename for IPC socket/pipe within the datadir (explicit paths escape it)

You'll need to use your own programming environments' capabilities (libraries, tools, etc) to
connect via HTTP, WS or IPC to a `ginb` node configured with the above flags and you'll
need to speak [JSON-RPC](https://www.jsonrpc.org/specification) on all transports. You
can reuse the same connection for multiple requests!

**Note: Please understand the security implications of opening up an HTTP/WS based
transport before doing so! Hackers on the internet are actively trying to subvert
Insight nodes with exposed APIs! Further, all browser tabs can access locally
running web servers, so malicious web pages could try to subvert locally available
APIs!**

### Operating a private network

Maintaining your own private network is more involved as a lot of configurations taken for
granted in the official networks need to be manually set up.

#### Defining the private genesis state

First, you'll need to create the genesis state of your networks, which all nodes need to be
aware of and agree upon. This consists of a small JSON file (e.g. call it `genesis.json`):

```json
{
  "config": {
    "chainId": 891,
    "homesteadBlock": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "vdpos": {
      "period": 3,
      "signerPeriod": 3,
      "signerBlocks": 6,
      "epoch": 201600,
      "maxSignersCount": 21, 
      "minVoterBalance": 1000000000000000000,
      "genesisTimestamp": 1561544470,
      "signers": [
        "0x891b2388ce73356917b21ca54f3039cbdfc29313",
        "0x4643ce2d6d4fe02e2b57070806364dde9eb8cac9",
        "0x230cf5081833c4f16e69e102ea00a4583a33cb11"
      ],
  "enodes":[
            {"address":"0x891b2388ce73356917b21ca54f3039cbdfc29313",
            "id":"327d1a41974ad0a672d9b3dcfada5a934b4c21207e95a40d534bde44c2f7b39c4f10dda7a7bc060c00868a77b522878ab960dff2f23f463616736a1e6e39ea93",
            "ip":"192.168.1.181",
            "port":"30001",
            "name":"inb",
            "nation":"China",
            "city":"beijing",
            "image":"www.image.com",
            "website":"www.insightchain.io",
            "email":"insightchain@xx.com",
            "data":"{\"hobby\":\"money\",\"age\":\"21\"}"},

            {"address":"0x891b2388ce73356917b21ca54f3039cbdfc29313",
            "id":"327d1a41974ad0a672d9b3dcfada5a934b4c21207e95a40d534bde44c2f7b39c4f10dda7a7bc060c00868a77b522878ab960dff2f23f463616736a1e6e39ea93",
            "ip":"192.168.1.181",
            "port":"30001",
            "name":"inb",
            "nation":"China",
            "city":"beijing",
            "image":"www.image.com",
            "website":"www.insightchain.io",
            "email":"insightchain@xx.com",
            "data":"{\"hobby\":\"money\",\"age\":\"21\"}"},

            {"address":"0x891b2388ce73356917b21ca54f3039cbdfc29313",
            "id":"327d1a41974ad0a672d9b3dcfada5a934b4c21207e95a40d534bde44c2f7b39c4f10dda7a7bc060c00868a77b522878ab960dff2f23f463616736a1e6e39ea93",
            "ip":"192.168.1.181",
            "port":"30001",
            "name":"inb",
            "nation":"China",
            "city":"beijing",
            "image":"www.image.com",
            "website":"www.insightchain.io",
            "email":"insightchain@xx.com",
            "data":"{\"hobby\":\"money\",\"age\":\"21\"}"},
]
}
```

The above fields should be fine for most purposes, although we'd recommend changing
the `nonce` to some random value so you prevent unknown remote nodes from being able
to connect to you. If you'd like to pre-fund some accounts for easier testing, you can
populate the `alloc` field with account configs:

```json
"alloc": {
  "0x0000000000000000000000000000000000000001": {
    "balance": "111111111"
  },
  "0x0000000000000000000000000000000000000002": {
    "balance": "222222222"
  }
}
```

With the genesis state defined in the above JSON file, you'll need to initialize **every**
`ginb` node with it prior to starting it up to ensure all blockchain parameters are correctly
set:

```shell
$ ginb init path/to/genesis.json
```

#### Creating the rendezvous point

With all nodes that you want to run initialized to the desired genesis state, you'll need to
start a bootstrap node that others can use to find each other in your network and/or over
the internet. The clean way is to configure and run a dedicated bootnode:

```shell
$ bootnode --genkey=boot.key
$ bootnode --nodekey=boot.key
```


*Note: You could also use a full-fledged `ginb` node as a bootnode, but it's the less
recommended way.*

#### Starting up your member nodes

With the bootnode operational and externally reachable (you can try
`telnet <ip> <port>` to ensure it's indeed reachable), start every subsequent `ginb`
node pointed to the bootnode for peer discovery via the `--bootnodes` flag. It will
probably also be desirable to keep the data directory of your private network separated, so
do also specify a custom `--datadir` flag.

```shell
$ ginb --datadir=path/to/custom/data/folder --bootnodes=<bootnode-enode-url-from-above>
```

*Note: Since your network will be completely cut off from the main and test networks, you'll
also need to configure a miner to process transactions and create new blocks for you.*

#### Running a private miner

Mining on the public Insight network is a complex task as it's only feasible using GPUs,
requiring an OpenCL or CUDA enabled `inbminer` instance. For information on such a
setup

In a private network setting, however a single CPU miner instance is more than enough for
practical purposes as it can produce a stable stream of blocks at the correct intervals
without needing heavy resources (consider running on a single thread, no need for multiple
ones either). To start a `ginb` instance for mining, run it with all your usual flags, extended
by:

```shell
$ ginb <usual-flags> --mine --minerthreads=1 --inberbase=0x0000000000000000000000000000000000000000
```




