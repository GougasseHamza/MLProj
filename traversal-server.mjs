import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const marker = "HOSTINGER_NODE_OUTPUT_TRAVERSAL_CONTROL:r211";
const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number.parseInt(process.env.PORT ?? "3000", 10);

const server = http.createServer((request, response) => {
  if (request.url !== "/h1-output-r211") {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ marker, error: "not_found" }));
    return;
  }
  let control;
  try {
    const body = fs.readFileSync(path.join(root, "control.txt"));
    control = { readable: true, bytes: body.length, sha256: crypto.createHash("sha256").update(body).digest("hex") };
  } catch (error) {
    control = { readable: false, errorCode: error.code ?? error.name };
  }
  response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify({
    authorization: "Hostinger HackerOne; researcher-owned Node site and exact same-account output traversal canary",
    marker,
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    control,
  }));
});

server.listen(port, "0.0.0.0", () => console.log(`${marker}:LISTENING:${port}`));
