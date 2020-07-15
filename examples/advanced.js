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
const TO_BE_RAWED = ['D2GS_LOADACT']


const sniffer = listen(networkInterface, version, true)
sniffer.on('inData', message => {
  if (TO_BE_RAWED.includes(message.name)) {
    console.log(`Incoming message raw-ed: $ ${JSON.stringify(message.name)}-${JSON.stringify(message.params)}-${JSON.stringify(message.raw.toString('hex'))}`)
  } else {
    console.log(`Incoming message: ${JSON.stringify(message.name)}-${JSON.stringify(message.params)}`)
  }
})
sniffer.on('outData', message => {
  console.log(`Outgoing message: ${JSON.stringify(message.name)}-${JSON.stringify(message.params)}`)
})

sniffer.on('error', err => {
  console.log(`Error: ${JSON.stringify(err)}`)
})

console.log(`Loaded sniffer on network interface ${networkInterface} with version ${version}`)
