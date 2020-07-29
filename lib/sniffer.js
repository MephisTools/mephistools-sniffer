const EventEmitter = require('events').EventEmitter
const { ClientD2gs, ClientSid, ClientMcp, ClientDiablo } = require('diablo2-protocol')

const byteToHex = []

for (let n = 0; n <= 0xff; ++n)
{
  const hexOctet = n.toString(16).padStart(2, '0')
  byteToHex.push(hexOctet)
}

function hex(arrayBuffer)
{
  const buff = new Uint8Array(arrayBuffer)
  const hexOctets = [] // new Array(buff.length) is even faster (preallocates necessary array size), then use hexOctets[i] instead of .push()

  for (let i = 0; i < buff.length; ++i)
    hexOctets.push(byteToHex[buff[i]])

  return hexOctets.join("")
}

function listen (networkInterface, version, includeRaw) {
  const pcap = require('pcap')
  const tcpTracker = new pcap.TCPTracker()
  let clientPortSid = null
  const sidPort = '6112' // TODO: ips/ports should be diablo2-data constants
  const d2gsPort = '4000'
  const mcpPort = '6113'
  let mcpIp = null
  const sniffer = new EventEmitter()
  const trackedPorts = new Set([sidPort, d2gsPort, mcpPort])
  const clientSid = new ClientSid(version)
  const clientMcp = new ClientMcp(version)
  const clientD2gs = new ClientD2gs(version, false, includeRaw)
  const clientDiablo = new ClientDiablo(version)
  clientDiablo.setClientSid(clientSid)
  clientDiablo.setClientMcp(clientMcp)
  clientDiablo.setClientD2gs(clientD2gs)
  clientDiablo.on('packet', packet => packet.toServer
    ? sniffer.emit('outData', packet)
    : sniffer.emit('inData', packet)
  )
  clientDiablo.on('error', err => sniffer.emit('error', err))
  const pcapSession = pcap.createSession(networkInterface, 'ip proto \\tcp')
  pcapSession.on('packet', function (rawPacket) {
    const packet = pcap.decode.packet(rawPacket)
    tcpTracker.track_packet(packet)
  })

  // tracker emits sessions, and sessions emit data
  tcpTracker.on('session', function (session) {
    const srcPort = session.src_name.split(':')[1]
    const dstPort = session.dst_name.split(':')[1]
    const srcIp = session.src_name.split(':')[0]
    const dstIp = session.dst_name.split(':')[0]
    if (!trackedPorts.has(srcPort) && !trackedPorts.has(dstPort)) {
      return
    }
    session.on('start', function () {
    })
    session.on('data send', function (_session, data) {
      // console.log(`Sent ${JSON.stringify(_session)}, ${hex(data)}`)

      if (srcPort === d2gsPort) {
        clientD2gs.parse(data, false)
      }

      if (dstPort === d2gsPort) {
        clientD2gs.parse(data, true)
      }

      if (srcPort === mcpPort && (srcIp === mcpIp || mcpIp === null)) {
        clientMcp.parse(data, false)
      }

      if (dstPort === mcpPort && (dstIp === mcpIp || mcpIp === null)) {
        clientMcp.parse(data, true)
      }

      if (dstPort === sidPort && data.length === 1 && data[0] === 1) {
        clientPortSid = srcPort
        return
      }

      if (srcPort === sidPort && dstPort === clientPortSid && (srcIp !== mcpIp || mcpIp === null)) {
        clientSid.parse(data, false)
      }

      if (dstPort === sidPort && srcPort === clientPortSid && (dstIp !== mcpIp || mcpIp === null)) {
        clientSid.parse(data, true)
      }
    })
    session.on('data recv', function (_session, data) {
      // console.log(`Received ${JSON.stringify(_session)}, ${hex(data)}`)

      if (srcPort === d2gsPort) {
        clientD2gs.parse(data, true)
      }

      if (dstPort === d2gsPort) {
        clientD2gs.parse(data, false)
      }

      if (srcPort === mcpPort && (srcIp === mcpIp || mcpIp === null)) {
        clientMcp.parse(data, true)
      }

      if (dstPort === mcpPort && (dstIp === mcpIp || mcpIp === null)) {
        clientMcp.parse(data, false)
      }

      if (srcPort === sidPort && data.length === 1 && data[0] === 1) {
        clientPortSid = dstPort
        return
      }

      if (srcPort === sidPort && dstPort === clientPortSid && (srcIp !== mcpIp || mcpIp === null)) {
        clientSid.parse(data, true)
      }

      if (dstPort === sidPort && srcPort === clientPortSid && (dstIp !== mcpIp || mcpIp === null)) {
        clientSid.parse(data, false)
      }
    })
    session.on('end', function () {
    })
  })

  return sniffer
}

module.exports = listen
