import fs from "node:fs";
import path from "node:path";

const marker = "HOSTINGER_NODE_RELATIVE_SYMLINK_GATE:r210";
const output = process.cwd();

let directRead;
try {
  const body = fs.readFileSync("/usr/sbin/proxyexec");
  directRead = { readable: true, bytes: body.length };
} catch (error) {
  directRead = { readable: false, errorCode: error.code ?? error.name };
}

console.log(JSON.stringify({
  marker,
  directRead,
  outputEntries: fs.readdirSync(output).sort().slice(0, 64),
  rootProbeIsSymlink: fs.lstatSync(path.join(output, "root-owned-probe")).isSymbolicLink(),
  missingProbeIsSymlink: fs.lstatSync(path.join(output, "missing-probe")).isSymbolicLink(),
}));
