const EventEmitter = require('events').EventEmitter
const { ClientD2gs } = require('diablo2-protocol')

function listen (networkInterface, version, includeRaw) {
  const pcap = require('pcap')
  const tcpTracker = new pcap.TCPTracker()
  const sidPort = '6112' // TODO: ips/ports should be diablo2-data constants
  const d2gsPort = '4000'
  const mcpPort = '6113'
  const sniffer = new EventEmitter()
  const trackedPorts = new Set([sidPort, d2gsPort, mcpPort])
  const clientD2gs = new ClientD2gs(version, false, includeRaw)
  clientD2gs.on('packet', packet => packet.toServer
    ? sniffer.emit('outData', packet)
    : sniffer.emit('inData', packet)
  )
  clientD2gs.on('error', err => sniffer.emit('error', err))
  const handleD2gsToClient = (data) => {
    clientD2gs.parse(data, false)
  }

  const handleD2gsToServer = (data) => {
    clientD2gs.parse(data, true)
  }

  const pcapSession = pcap.createSession(networkInterface, 'ip proto \\tcp')
  pcapSession.on('packet', function (rawPacket) {
    const packet = pcap.decode.packet(rawPacket)
    tcpTracker.track_packet(packet)
  })

  // tracker emits sessions, and sessions emit data
  tcpTracker.on('session', function (session) {
    const srcPort = session.src_name.split(':')[1]
    const dstPort = session.dst_name.split(':')[1]
    if (!trackedPorts.has(srcPort) && !trackedPorts.has(dstPort)) {
      return
    }
    session.on('start', function () {
    })
    session.on('data send', function (_session, data) {
      if (srcPort === d2gsPort) {
        handleD2gsToClient(data)
      }

      if (dstPort === d2gsPort) {
        handleD2gsToServer(data)
      }
    })
    session.on('data recv', function (_session, data) {
      if (srcPort === d2gsPort) {
        handleD2gsToServer(data)
      }

      if (dstPort === d2gsPort) {
        handleD2gsToClient(data)
      }
    })
    session.on('end', function () {
    })
  })

  return sniffer
}

module.exports = listen
