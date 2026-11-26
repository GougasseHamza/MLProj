import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const marker = "HOSTINGER_NODE_RELATIVE_SYMLINK_GATE:r210";
const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number.parseInt(process.env.PORT ?? "3000", 10);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function inspect(name) {
  const target = path.join(root, name);
  const result = { name };
  try {
    const stat = fs.lstatSync(target);
    result.type = stat.isSymbolicLink() ? "symlink" : stat.isFile() ? "file" : stat.isDirectory() ? "directory" : "other";
    result.mode = stat.mode & 0o7777;
    result.uid = stat.uid;
    result.gid = stat.gid;
    result.lstatBytes = stat.size;
    if (stat.isSymbolicLink()) result.linkTarget = fs.readlinkSync(target);
  } catch (error) {
    result.type = "absent";
    result.lstatErrorCode = error.code ?? error.name;
    return result;
  }
  try {
    const body = fs.readFileSync(target);
    result.read = { readable: true, bytes: body.length, sha256: sha256(body) };
  } catch (error) {
    result.read = { readable: false, errorCode: error.code ?? error.name };
  }
  return result;
}

const server = http.createServer((request, response) => {
  if (request.url !== "/h1-publisher-r210") {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ marker, error: "not_found" }));
    return;
  }
  response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify({
    authorization: "Hostinger HackerOne; researcher-owned Node site; fixed root-owned non-secret canary and nonexistent negative",
    marker,
    identity: {
      uid: typeof process.getuid === "function" ? process.getuid() : null,
      gid: typeof process.getgid === "function" ? process.getgid() : null,
    },
    objects: ["control.txt", "root-owned-probe", "missing-probe"].map(inspect),
  }));
});

server.listen(port, "0.0.0.0", () => console.log(`${marker}:LISTENING:${port}`));
