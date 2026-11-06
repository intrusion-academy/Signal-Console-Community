// Zip archives, written and read by hand with Node's own zlib - no
// dependency: the report's Word file (src/documents.js), the release
// package (scripts/release.js) and its unpacking by the updater
// (src/updates.js). Plain zip only (no ZIP64, no encryption): every file
// this console writes or reads is far below 4 GB and 65,535 entries.
'use strict';

const zlib = require('zlib');

// zip packs files [{name, data}] into a zip archive, each deflated.
function zip(files) {
  const now = new Date();
  const date = ((now.getUTCFullYear() - 1980) << 9) | ((now.getUTCMonth() + 1) << 5) | now.getUTCDate();
  const parts = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name);
    const raw = Buffer.from(f.data);
    const data = zlib.deflateRawSync(raw);
    const crc = zlib.crc32(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(8, 10);
    entry.writeUInt16LE(date, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(data.length, 20);
    entry.writeUInt32LE(raw.length, 24);
    entry.writeUInt16LE(name.length, 28);
    entry.writeUInt32LE(offset, 42);
    parts.push(local, name, data);
    central.push(entry, name);
    offset += local.length + name.length + data.length;
  }
  const dir = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(dir.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, dir, end]);
}

// unzip reads a zip archive's files [{name, data}] from its central
// directory - stored or deflated entries - checking each one's CRC-32 and
// size, and refusing a name that would leave the folder it is unpacked
// into (absolute, a drive, or ..). A folder entry (a name ending in /) is
// left out.
function unzip(buf) {
  const endAt = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (endAt < 0 || endAt + 22 > buf.length) throw new Error('not a zip archive');
  const count = buf.readUInt16LE(endAt + 10);
  let p = buf.readUInt32LE(endAt + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('zip: damaged central directory');
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith('/')) continue;
    if (/^[\\/]|^[a-zA-Z]:|(^|[\\/])\.\.([\\/]|$)/.test(name)) throw new Error(`zip: ${name}: a path outside the folder`);
    if (buf.readUInt32LE(local) !== 0x04034b50) throw new Error(`zip: ${name}: damaged entry`);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const raw = buf.subarray(start, start + csize);
    let data;
    if (method === 0) data = Buffer.from(raw);
    else if (method === 8) data = zlib.inflateRawSync(raw);
    else throw new Error(`zip: ${name}: compression method ${method} is not read`);
    if (data.length !== size || zlib.crc32(data) !== crc) throw new Error(`zip: ${name}: damaged (size or CRC-32)`);
    out.push({ name, data });
  }
  return out;
}

module.exports = { zip, unzip };
