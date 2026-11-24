import http from "node:http";

const marker = "HOSTINGER_NODE_RUNTIME_CONTROL:a0034-r1";
const port = Number.parseInt(process.env.PORT ?? "3000", 10);

const server = http.createServer((request, response) => {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(
    JSON.stringify({
      marker,
      path: request.url,
      node: process.version,
      uid: typeof process.getuid === "function" ? process.getuid() : null,
      gid: typeof process.getgid === "function" ? process.getgid() : null,
    })
  );
});

server.listen(port, "0.0.0.0", () => {
  console.log(`${marker}:LISTENING:${port}`);
});

