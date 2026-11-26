import fs from "node:fs";
import path from "node:path";

const marker = "HOSTINGER_NODE_USRSBIN_DIRECTORY_SYMLINK_GATE:r219";
const output = path.resolve("dist");
fs.rmSync(output, { recursive: true, force: true });
const linkTarget = "../../../../../../../usr/sbin";
let outputLink;
try {
  fs.symlinkSync(linkTarget, output);
  outputLink = { created: true, target: linkTarget, isSymlink: fs.lstatSync(output).isSymbolicLink() };
} catch (error) {
  outputLink = { created: false, target: linkTarget, errorCode: error.code ?? error.name };
}

let directRead;
try {
  const body = fs.readFileSync("/usr/sbin/proxyexec");
  directRead = { readable: true, bytes: body.length };
} catch (error) {
  directRead = { readable: false, errorCode: error.code ?? error.name };
}

let linkRead;
try {
  const body = fs.readFileSync(output);
  linkRead = { readable: true, bytes: body.length };
} catch (error) {
  linkRead = { readable: false, errorCode: error.code ?? error.name };
}

let outputStat;
try {
  const stat = fs.statSync(output);
  outputStat = { available: true, isFile: stat.isFile(), isDirectory: stat.isDirectory(), bytes: stat.size };
} catch (error) {
  outputStat = { available: false, errorCode: error.code ?? error.name };
}

let outputSummary;
try {
  const names = fs.readdirSync(output);
  let regularFiles = 0;
  let readableRegularFiles = 0;
  for (const name of names) {
    try {
      const stat = fs.lstatSync(path.join(output, name));
      if (stat.isFile()) {
        regularFiles += 1;
        try { fs.accessSync(path.join(output, name), fs.constants.R_OK); readableRegularFiles += 1; } catch {}
      }
    } catch {}
  }
  outputSummary = { available: true, entryCount: names.length, regularFiles, readableRegularFiles };
} catch (error) {
  outputSummary = { available: false, errorCode: error.code ?? error.name };
}

console.log(JSON.stringify({
  marker,
  directRead,
  linkRead,
  outputLink,
  outputStat,
  outputSummary,
  outputRelativeToRepository: path.relative(process.cwd(), output),
}));
