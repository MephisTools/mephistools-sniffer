const {
  supportedVersions,
  defaultVersion
} = require('diablo2-protocol')

const { listen } = require('../index')
if (process.argv.length < 3) {
  console.log('Usage : sudo node sniffer.js <networkInterface> [version]')
  process.exit(1)
}

let version
// If the version correspond to a supported version else use default
if (process.argv.length > 3) {
  version = supportedVersions.find(v => v === process.argv[3]) ? process.argv[3] : defaultVersion
}
const networkInterface = process.argv[2]

const sniffer = listen(networkInterface, version)
sniffer.on('inData', message => {
  console.log(`Incoming low level message: ${JSON.stringify(message)}`)
})
sniffer.on('outData', message => {
  console.log(`Outgoing low level message: ${JSON.stringify(message)}`)
})

sniffer.on('error', err => {
  console.log(`Error: ${JSON.stringify(err)}`)
})

console.log(`Loaded sniffer on network interface ${networkInterface} with version ${version}`)
