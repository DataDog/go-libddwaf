#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { get } from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const __dirname = dirname(fileURLToPath(import.meta.url));

const owner = 'DataDog';
const repo = 'libddwaf';

const { tag_name: version, assets } = await getJSON(`https://api.github.com/repos/${owner}/${repo}/releases/latest`);
console.log(`Latest libddwaf release: v${version}`);

const currentVersion = await fs.readFile(resolve(__dirname, '.version'), 'utf-8');
if (version === currentVersion) {
  console.log('Already up-to-date, nothing to do!');
  process.exit(0);
}

const flavors = {
  'darwin-amd64': { os: 'darwin', arch: 'x86_64', ext: 'dylib' },
  'darwin-arm64': { os: 'darwin', arch: 'arm64', ext: 'dylib' },
  'linux-amd64': { os: 'linux', arch: 'x86_64', ext: 'so' },
  'linux-arm64': { os: 'linux', arch: 'aarch64', ext: 'so' },
};

let wroteInclude = false;

for (const [name, { os, arch, ext }] of Object.entries(flavors)) {
  console.debug(`Looking up asset for ${name}...`);
  const dirName = `libddwaf-${version}-${os}-${arch}`;
  const tarName = `${dirName}.tar.gz`;
  const tar = assets.find(({ name }) => name === tarName);
  if (tar == null) {
    throw new Error(`No artifact named '${tarName}' was found!`);
  }
  const shaName = `${tarName}.sha256`;
  const sha = assets.find(({ name }) => name === shaName);
  if (sha == null) {
    throw new Error(`No artifact named '${shaName}' was found!`);
  }


  console.debug(`... downloading from ${tar.url}`);
  const [tarball, hash] = await download(tar.browser_download_url);
  const [sha256] = await download(sha.browser_download_url, 'utf-8');
  const expectedHash = sha256.split(/\s+/)[0];
  if (expectedHash !== hash) {
    throw new Error(`Checksum mismatch for ${tar.browser_download_url}: \nExpected: ${expectedHash} \nActual:   ${hash}`);
  }

  const tmp = await fs.mkdtemp(resolve(tmpdir(), dirName));
  try {
    const file = resolve(tmp, 'libddwaf.tar.gz');
    await fs.writeFile(file, tarball);
    await runCommand('tar', 'zxf', file, '-C', tmp);

    const include = resolve(tmp, dirName, 'include');
    const includeDir = resolve(__dirname, '..', 'include');
    if (!wroteInclude) {
      for (const file of await fs.readdir(includeDir)) {
        if (file !== 'vendor.go') {
          await fs.rm(resolve(includeDir, file), { force: true, recursive: true });
        }
      }
      await copy(include, includeDir);
      wroteInclude = true;
    } else {
      for (const file of await fs.readdir(include)) {
        const expected = await fs.readFile(resolve(include, file));
        const actual = await fs.readFile(resolve(includeDir, file));

        if (!isDeepStrictEqual(expected, actual)) {
          throw new Error(`Mismatched include file: ${file}`);
        }
      }
    }

    const lib = resolve(tmp, dirName, 'lib', `libddwaf.${ext}`);
    await fs.copyFile(lib, resolve(__dirname, name, `libddwaf.${ext}`));
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
}

await fs.writeFile(resolve(__dirname, '.version'), version);

console.log(`Successfully updated embedded libraries from v${currentVersion} to v${version}!`);

async function copy(from, to) {
  const stat = await fs.stat(from);
  if (stat.isDirectory()) {
    await fs.mkdir(to, { recursive: true });
    for (const file of await fs.readdir(from)) {
      await copy(resolve(from, file), resolve(to, file));
    }
    return;
  }

  await fs.copyFile(from, to);
}

function download(url, encoding) {
  return new Promise((ok, ko) => {
    get(
      url,
      {
        headers: {
          'User-Agent': `node / ${process.versions.node}`,
        },
      },
      (response) => {
        const chunks = new Array();
        const hash = createHash('sha256');
        response.on('data', (chunk) => {
          hash.update(chunk);
          chunks.push(Buffer.from(chunk));
        });
        response.once('error', ko);
        response.once('end', () => {
          try {
            const body = Buffer.concat(chunks);
            if (response.statusCode === 302) {
              return ok(download(response.headers['location'], encoding));
            }
            if (response.statusCode !== 200) {
              throw new Error(`GET ${url}: HTTP ${response.statusCode} --${response.statusMessage}\n${body}`);
            }

            const digest = hash.digest('hex');
            if (encoding == null) {
              ok([body, digest]);
            } else {
              ok([body.toString(encoding), digest]);
            }
          } catch (e) {
            ko(e);
          }
        });
      },
    ).once('error', ko);
  });
}

function getJSON(url) {
  return new Promise((ok, ko) => {
    get(
      url,
      {
        headers: {
          'Accept': 'application/vnd.github+json',
          'User-Agent': `node / ${process.versions.node}`,
          'X-Github-Api-Version': '2022-11-28',
        },
      },
      (response) => {
        const chunks = new Array();
        response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        response.once('error', ko);
        response.once('end', () => {
          try {
            const body = Buffer.concat(chunks).toString('utf-8');
            if (response.statusCode !== 200) {
              throw new Error(`GET ${url}: HTTP ${response.statusCode} --${response.statusMessage}\n${body}`);
            }
            ok(JSON.parse(body));
          } catch (e) {
            ko(e);
          }
        });
      },
    ).once('error', ko);
  });
}

function runCommand(cmd, ...args) {
  return new Promise((ok, ko) => {
    const child = execFile(cmd, args, { shell: true, stdio: ['inherit', 'ipc', 'ipc'] });
    const stdout = [];
    child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk)));
    const stderr = [];
    child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)));

    child.once('error', ko);
    child.once('close', (code, signal) => {
      if (code === 0) {
        return ok();
      }
      const reason = code != null
        ? `code ${code}`
        : `signal ${signal}`;
      const err = new Error(`${cmd} ${args.join(' ')}: exited with ${reason}`);
      err.code = code;
      err.signal = signal;
      err.stdout = stdout;
      err.stderr = stderr;
      ko(err);
    });
  });
}
