
# mephistools-sniffer

<!-- PROJECT SHIELDS -->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![NPM version](https://img.shields.io/npm/v/mephistools-sniffer.svg)](npm-url)
[![Build Status](https://github.com/Mephistools/mephistools-sniffer/workflows/CI/badge.svg)](build-url)
[![Discord](https://img.shields.io/badge/chat-on%20discord-brightgreen.svg)](discord-url)

<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
  * [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Acknowledgements](#acknowledgements)

<!-- ABOUT THE PROJECT -->
## About The Project

![demo](docs/images/demo.gif)

The goal of this project is to provide an easy-to-use lib to sniff Diablo 2 packets using either

* [diablo2-protocol](https://github.com/MephisTools/diablo2-protocol) for the low level data

 either

* [AutoTathamet](https://github.com/MephisTools/AutoTathamet) for the high level data (uses internally diablo2-protocol)

 either both: in order to be able to get both low level and high level data.

 Currently, it works but the code is pretty dirty.

### Built With

This section should list any major frameworks that you built your project using. Leave any add-ons/plugins for the acknowledgements section. Here are a few examples.

<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

### Installation

```bash
npm i mephistools-sniffer
```

<!-- USAGE EXAMPLES -->
## Usage

```js
const { listen } = require('mephistools-sniffer')
const sniffer = listen('my-network-interface', 'my-diablo2-version')
sniffer.on('inData', message => {
  console.log(`Incoming low level message: ${JSON.stringify(message)}`)
})
sniffer.on('outData', message => {
  console.log(`Outgoing low level message: ${JSON.stringify(message)}`)
})

sniffer.on('error', err => {
  console.log(`Error: ${JSON.stringify(err)}`)
})
```

Or run the example

```bash
# Requires sudo because pcap you know ...
sudo node examples/basic.js my-network-interface my-diablo2-version
```

<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/Mephistools/mephistools-sniffer/issues) for a list of proposed features (and known issues).

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements

* [GitHub Emoji Cheat Sheet](https://www.webpagefx.com/tools/emoji-cheat-sheet)
* [Img Shields](https://shields.io)
* [Choose an Open Source License](https://choosealicense.com)
* [GitHub Pages](https://pages.github.com)

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/Mephistools/mephistools-sniffer.svg?style=flat-square
[contributors-url]: https://github.com/Mephistools/mephistools-sniffer/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/Mephistools/mephistools-sniffer.svg?style=flat-square
[forks-url]: https://github.com/Mephistools/mephistools-sniffer/network/members
[stars-shield]: https://img.shields.io/github/stars/Mephistools/mephistools-sniffer.svg?style=flat-square
[stars-url]: https://github.com/Mephistools/mephistools-sniffer/stargazers
[issues-shield]: https://img.shields.io/github/issues/Mephistools/mephistools-sniffer.svg?style=flat-square
[issues-url]: https://github.com/Mephistools/mephistools-sniffer/issues
[license-shield]: https://img.shields.io/github/license/Mephistools/mephistools-sniffer.svg?style=flat-square
[license-url]: https://github.com/Mephistools/mephistools-sniffer/blob/master/LICENSE.txt
[npm-shield]: https://img.shields.io/npm/v/mephistools-sniffer.svg
[npm-url]: http://npmjs.com/package/mephistools-sniffer
[build-shield]: https://github.com/Mephistools/mephistools-sniffer/workflows/CI/badge.svg
[build-url]: https://github.com/Mephistools/mephistools-sniffer/actions?query=workflow%3A%22CI%22
[discord-shield]: https://img.shields.io/badge/chat-on%20discord-brightgreen.svg
[discord-url]: https://discord.gg/9RqtApv
