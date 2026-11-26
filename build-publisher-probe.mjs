import fs from "node:fs";
import path from "node:path";

const marker = "HOSTINGER_NODE_OUTPUT_TRAVERSAL_CONTROL:r211";
const output = path.resolve("..", "h1-output-r211");
fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
fs.copyFileSync("traversal-server.mjs", path.join(output, "server.mjs"));
fs.writeFileSync(path.join(output, "control.txt"), `${marker}:4bb311b8f1d74dbe\n`, { mode: 0o600 });

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
  outputRelativeToRepository: path.relative(process.cwd(), output),
}));
