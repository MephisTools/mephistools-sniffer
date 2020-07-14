const {
  supportedVersions,
  defaultVersion,
  protocol,
  createSplitter,
  decompress,
  d2gsReader,
  itemParser,
  bitfieldLE
} = require('diablo2-protocol')

// TODO: version optional
if (process.argv.length < 3) {
  console.log('Usage : sudo node sniffer.js <networkInterface> [version]')
  process.exit(1)
}

let version
// If the version correspond to a supported version else use default
if (process.argv.length > 3) {
  version = supportedVersions.find(v => v === process.argv[3]) ? process.argv[3] : defaultVersion
}

const Parser = require('protodef').Parser
const networkInterface = process.argv[2]

const pcap = require('pcap')

const tcpTracker = new pcap.TCPTracker()

const WebSocket = require('ws')

const wss = new WebSocket.Server({ port: 8080 })

// Broadcast to all.
wss.broadcast = function broadcast (data) {
  wss.clients.forEach(function each (client) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data)
    }
  })
}

const pcapSession = pcap.createSession(networkInterface, 'ip proto \\tcp')
pcapSession.on('packet', function (rawPacket) {
  const packet = pcap.decode.packet(rawPacket)
  tcpTracker.track_packet(packet)
})

const FullPacketParser = require('protodef').Parser
const ProtoDef = require('protodef').ProtoDef

const mcpToServer = new ProtoDef(false)
mcpToServer.addProtocol(protocol[version].mcp, ['toServer'])

const mcpToClient = new ProtoDef(false)
mcpToClient.addProtocol(protocol[version].mcp, ['toClient'])

const sidToServer = new ProtoDef(false)
sidToServer.addProtocol(protocol[version].sid, ['toServer'])

const sidToClient = new ProtoDef(false)
sidToClient.addProtocol(protocol[version].sid, ['toClient'])

const bnftpToServer = new ProtoDef(false)
bnftpToServer.addProtocol(protocol[version].bnftp, ['toServer'])

const bnftpToClient = new ProtoDef(false)
bnftpToClient.addProtocol(protocol[version].bnftp, ['toClient'])

const d2gsToClient = new ProtoDef(false)
d2gsToClient.addTypes(d2gsReader)
d2gsToClient.addTypes(bitfieldLE)
d2gsToClient.addProtocol(protocol[version].d2gs, ['toClient'])

const d2gsToServer = new ProtoDef(false)
d2gsToServer.addProtocol(protocol[version].d2gs, ['toServer'])

const toClientParser = new FullPacketParser(d2gsToClient, 'packet')
const splitter = createSplitter()
splitter.sloppyMode = true

splitter.on('data', data => {
  const uncompressedData = decompress(data)

  toClientParser.write(uncompressedData)
})

function handleD2gsToClient (name, params, data, buffer) {
  console.log(`raw d2gsToClient ${buffer === null ? data.toString('hex') : buffer.toString('hex')} length: ${buffer === null ? data.length : buffer.length}`)

  if (name === 'D2GS_ITEMACTIONWORLD' || name === 'D2GS_ITEMACTIONOWNED') {
    params = itemParser(buffer !== null ? buffer : data)
  } else if (name === 'D2GS_LOADACT') {
    console.log(`Got map seed ${params.mapId}`)
    console.log(`Raw: ${buffer === null ? data.toString('hex') : buffer.toString('hex')}`)
  }
  wss.broadcast(JSON.stringify({ protocol: 'd2gsToClient', name, params }))
  console.log(`d2gsToClient : ${name} ${JSON.stringify(params)}`)
}

toClientParser.on('data', ({ data, buffer }) => {
  const { name, params } = data
  handleD2gsToClient(name, params, data, buffer)
})

let clientPortSid = null
let clientPortBnFtp = null
let compression = false

// server ports
const sidPort = '6112'
const d2gsPort = '4000'
let mcpPort = '6113'
let mcpIp = null
// const IGNORED_PACKETS = [0xAF, /*0x01, 0x9d, 0x09,*/ 0xf1, 0x02] // Non debugged packets that just pollute
const LOGIN_PACKETS = [0xAF]
// const TO_BE_RAWED = [0x01]

const trackedPorts = new Set([sidPort, d2gsPort, mcpPort])
function displayD2gsToClient (data) {
  // if (IGNORED_PACKETS.includes(data[0])) {
  //   console.log(`ignored packet: ${data[0]}`)
  //   return
  // }

  try {
    if (!compression) {
      if (version === 1.13 && !LOGIN_PACKETS.includes(data[0])) { data = data.slice(1) }
      const parsed = d2gsToClient.parsePacketBuffer('packet', data).data
      const { name, params } = parsed
      if (name === 'D2GS_NEGOTIATECOMPRESSION') {
        if (params.compressionMode !== 0) {
          console.log('enable compression')
          compression = true
        } else {
          console.log('compression is deactivated')
        }
      }
      handleD2gsToClient(name, params, data, null)
    } else {
      splitter.write(data)
    }
  } catch (error) {
    console.log(`d2gsToClient : ${error.message}`)
    console.log(`raw d2gsToClient ${data.toString('hex')} length: ${data.length}`)
  }
}

function displayParsed (proto, protoName, data, raw = false) {
  try {
    const { name, params } = proto.parsePacketBuffer('packet', data).data
    console.log(`${protoName} : ${name} ${JSON.stringify(params)}`)
    wss.broadcast(JSON.stringify({ protocol: protoName, name, params }))
    if (raw) console.log(`raw ${protoName} ${name} ${data.toString('hex')}`)
    return { name, params }
  } catch (error) {
    if (raw) console.log(`raw ${protoName} ${data.toString('hex')}`)
    console.log(`${protoName}:${error.message}`)
  }
}

function displayD2gsToServer (data) {
  displayParsed(d2gsToServer, 'd2gsToServer', data)
}

function displayMcpToServer (data) {
  displayParsed(mcpToServer, 'mcpToServer', data)
}

function displayMcpToClient (data) {
  displayParsed(mcpToClient, 'mcpToClient', data)
}

function displaySidToServer (data) {
  displayParsed(sidToServer, 'sidToServer', data)
}

function displaySidToClient (data) {
  const parsed = displayParsed(sidToClient, 'sidToClient', data)
  if (parsed.name === 'SID_LOGONREALMEX') {
    const IP = parsed.params.IP
    mcpIp = IP[0] + '.' + IP[1] + '.' + IP[2] + '.' + IP[3]
    mcpPort = parsed.params.port + ''
    console.log(`received SID_LOGONREALMEX ${JSON.stringify({ mcpIp, mcpPort })}`)
  }
}

const challengeParserClient = new Parser(bnftpToClient, 'CHALLENGE')
challengeParserClient.on('error', err => console.log(`bnftpToClient challenge error : ${err.message}`))
challengeParserClient.on('data', (parsed) => {
  console.log(`bnftpToClient challenge : ${JSON.stringify(parsed)}`)
})

const protocolParserClient = new Parser(bnftpToClient, 'FILE_TRANSFER_PROTOCOL')
protocolParserClient.on('error', err => console.log(`bnftpToClient protocol error : ${err.message}`))
protocolParserClient.on('data', (parsed) => {
  console.log(`bnftpToClient protocol : ${JSON.stringify(parsed)}`)
})

function displayBnftpToClient (data) {
  try {
    protocolParserClient.write('FILE_TRANSFER_PROTOCOL')
  } catch (error) {
    console.log(`bnftpToClient error:  ${error}`)
    console.log(`bnftpToClient protocol: ${data}`)
  }
}

const challengeParserServer = new Parser(bnftpToServer, 'CHALLENGE')
challengeParserServer.on('error', err => console.log(`bnftpToServer bnftp error : ${err.message}`))
challengeParserServer.on('data', (parsed) => {
  console.log(`bnftpToServer challenge : ${JSON.stringify(parsed)}`)
})
const protocolParserServer = new Parser(bnftpToServer, 'FILE_TRANSFER_PROTOCOL')
protocolParserServer.on('error', err => console.log('bnftpToServer bnftp error : ', err.message))
protocolParserServer.on('data', (parsed) => {
  console.log(`bnftpToServer protocol : ${JSON.stringify(parsed)}`)
})
function displayBnftpToServer (data) {
  try {
    protocolParserServer.write('FILE_TRANSFER_PROTOCOL')
  } catch (error) {
    console.log(`bnftpToServer error: ${error}`)
    console.log(`bnftpToServer write challenge ${data}`)
  }
}

// tracker emits sessions, and sessions emit data
tcpTracker.on('session', function (session) {
  const srcPort = session.src_name.split(':')[1]
  const dstPort = session.dst_name.split(':')[1]
  const srcIp = session.src_name.split(':')[0]
  const dstIp = session.dst_name.split(':')[0]
  if (!trackedPorts.has(srcPort) && !trackedPorts.has(dstPort)) {
    return
  }

  /*
  if (dstPort === sidPort) {
    if (clientPortSid === null) {
      console.log('zalloooo')
      clientPortSid = srcPort
    } else {
      clientPortBnFtp = srcPort
    }
  }
  if (srcPort === sidPort) {
    if (clientPortSid === null) {
      clientPortSid = dstPort
    } else {
      clientPortBnFtp = dstPort
    }
  } */

  session.on('start', function () {
    if (srcPort === d2gsPort || dstPort === d2gsPort) {
      console.log('Start of d2gs session')
    }
    if ((srcPort === mcpPort || dstPort === mcpPort) && (dstIp === mcpIp || srcIp === mcpIp || mcpIp === null)) {
      console.log('Start of mcp session')
    }
    if ((srcPort === sidPort || dstPort === sidPort) && ((dstIp !== mcpIp && srcIp !== mcpIp) || mcpIp === null)) {
      console.log('Start of sid session')
    }
  })
  session.on('data send', function (session, data) {
    // Proxy mode
    if (srcPort === d2gsPort) {
      displayD2gsToClient(data)
    }

    if (dstPort === d2gsPort) {
      displayD2gsToServer(data)
    }

    if (srcPort === mcpPort && (srcIp === mcpIp || mcpIp === null)) {
      displayMcpToClient(data)
    }

    if (dstPort === mcpPort && (dstIp === mcpIp || mcpIp === null)) {
      displayMcpToServer(data)
    }

    if (dstPort === sidPort && data.length === 1 && data[0] === 1) {
      console.log(`sid on port ${srcPort} : ${data}`)
      clientPortSid = srcPort
      return
    }

    if (dstPort === sidPort && data.length === 1 && data[0] === 2) {
      console.log(`bnftp on port ${srcPort} : ${data}`)
      clientPortBnFtp = srcPort
      return
    }

    if (srcPort === sidPort && dstPort === clientPortSid && (srcIp !== mcpIp || mcpIp === null)) {
      displaySidToClient(data)
    }

    if (dstPort === sidPort && srcPort === clientPortSid && (dstIp !== mcpIp || mcpIp === null)) {
      displaySidToServer(data)
    }

    if (srcPort === sidPort && dstPort === clientPortBnFtp) {
      displayBnftpToClient(data)
    }

    if (dstPort === sidPort && srcPort === clientPortBnFtp) {
      displayBnftpToServer(data)
    }
  })
  session.on('data recv', function (session_, data) {
    if (srcPort === d2gsPort) {
      displayD2gsToServer(data)
    }

    if (dstPort === d2gsPort) {
      displayD2gsToClient(data)
    }

    if (srcPort === mcpPort && (srcIp === mcpIp || mcpIp === null)) {
      displayMcpToServer(data)
    }

    if (dstPort === mcpPort && (dstIp === mcpIp || mcpIp === null)) {
      displayMcpToClient(data)
    }

    if (srcPort === sidPort && data.length === 1 && data[0] === 1) {
      console.log(`sid on port ${dstPort} : ${data}`)
      clientPortSid = dstPort
      return
    }

    if (srcPort === sidPort && data.length === 1 && data[0] === 2) {
      console.log(`bnftp on port ${dstPort} : ${data}`)
      clientPortBnFtp = dstPort
      return
    }

    if (srcPort === sidPort && dstPort === clientPortSid && (srcIp !== mcpIp || mcpIp === null)) {
      displaySidToServer(data)
    }

    if (dstPort === sidPort && srcPort === clientPortSid && (dstIp !== mcpIp || mcpIp === null)) {
      displaySidToClient(data)
    }

    if (srcPort === sidPort && dstPort === clientPortBnFtp) {
      displayBnftpToServer(data)
    }

    if (dstPort === sidPort && srcPort === clientPortBnFtp) {
      displayBnftpToClient(data)
    }
  })

  session.on('end', function () {
    if (srcPort === d2gsPort || dstPort === d2gsPort) {
      console.log('End of d2gs session')
    }
    if ((srcPort === mcpPort || dstPort === mcpPort) && (dstIp === mcpIp || srcIp === mcpIp || mcpIp === null)) {
      console.log('End of mcp session')
    }
    if ((srcPort === sidPort || dstPort === sidPort) && (dstIp === mcpIp || srcIp === mcpIp || mcpIp === null)) {
      console.log('End of sid session')
    }
  })
})

console.log(`Loaded sniffer on network interface ${networkInterface} with version ${version}`)

/**
 * Start sniffing packets, passing messages somehow, low or high level according to given params ...
 */
function sniff () {
}