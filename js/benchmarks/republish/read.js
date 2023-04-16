import fs from 'fs'
import DHT from 'pkarr/lib/dht.js'

// Get next public key and signature
const filePath = './keys-signatures';
const lineLength = 194;
const line = Buffer.alloc(lineLength);
let fileOffset = 0;

const stat = fs.statSync(filePath)

// Open the file for reading
const fd = fs.openSync(filePath, 'r')
const v = Buffer.from('000b0c805b5b225f74657374222c227374696c6c20616c697665225d5d03', 'hex');

function next() {
  fs.readSync(fd, line, 0, lineLength, fileOffset);

  fileOffset += lineLength
  fileOffset = fileOffset % stat.size

  const str = line.toString().replace(/\n/g, '')
  const [key, sig] = str.split(':')
  return [
    Buffer.from(key, 'hex'),
    {
      v,
      seq: 1681656800,
      sig: Buffer.from(sig, 'hex')
    }
  ]
}

//  DHT

const dht = new DHT()
const x = await dht.put(...next())
console.log(x)

