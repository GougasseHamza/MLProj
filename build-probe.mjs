import https from "node:https";
import os from "node:os";

const marker = "HOSTINGER_NODE_BUILD_CONTROL:a0034-r1";
const callbackUrl = new URL(
  "https://147-182-179-38.sslip.io/hostinger-git-sentinel-9bd4c613/build-control-a0034-r1"
);

const identity = {
  marker,
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  uid: typeof process.getuid === "function" ? process.getuid() : null,
  gid: typeof process.getgid === "function" ? process.getgid() : null,
  cwdBasename: process.cwd().split("/").filter(Boolean).at(-1) ?? "",
  hostnameLength: os.hostname().length,
};

console.log(JSON.stringify(identity));

await new Promise((resolve) => {
  const request = https.get(
    callbackUrl,
    {
      headers: {
        "User-Agent": "hostinger-authorized-node-build-control-a0034-r1",
      },
      timeout: 10_000,
    },
    (response) => {
      response.resume();
      response.once("end", resolve);
    }
  );

  request.once("timeout", () => request.destroy(new Error("callback timeout")));
  request.once("error", (error) => {
    console.log(`CALLBACK_RESULT:${error.code ?? error.name}`);
    resolve();
  });
});

