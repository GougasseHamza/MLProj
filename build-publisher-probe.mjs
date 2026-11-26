import fs from "node:fs";
import path from "node:path";

const marker = "HOSTINGER_NODE_PUBLISHER_SYMLINK_GATE:r208";
const output = path.resolve("dist");
fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
fs.copyFileSync("publisher-server.mjs", path.join(output, "server.mjs"));
fs.writeFileSync(path.join(output, "control.txt"), `${marker}:CONTROL\n`, { mode: 0o600 });
fs.symlinkSync("/usr/sbin/proxyexec", path.join(output, "root-owned-probe"));
fs.symlinkSync("/root/hostinger-h1-nonexistent-r208", path.join(output, "missing-probe"));

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
  outputEntries: fs.readdirSync(output).sort(),
  rootProbeIsSymlink: fs.lstatSync(path.join(output, "root-owned-probe")).isSymbolicLink(),
  missingProbeIsSymlink: fs.lstatSync(path.join(output, "missing-probe")).isSymbolicLink(),
}));
