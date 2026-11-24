import { expect, test } from "bun:test";
import { hostname } from "node:os";
import { inflateSync } from "node:zlib";

test("README links the demo screenshots and documents security setup", async () => {
  const readme = await Bun.file("README.md").text();
  for (const term of [
    "OPENCODE_API_KEY", "OPENCODE_BASE_URL", "BASHO_HOST", "BASHO_PORT",
    "BASHO_AUTH_TOKEN", "BASHO_SECURITY_DB", "BASHO_DEMO_SECURITY=1",
    "BASHO_NTFY_TOKEN", "BASHO_DISCORD_WEBHOOK", "BASHO_TELEGRAM_BOT_TOKEN",
    "BASHO_TELEGRAM_CHAT_ID", "auto-lockdown", "sudoers.d", "UDP/41641",
  ]) expect(readme).toContain(term);

  for (const [name, width, height] of [
    ["security-desktop", 1440, 1080], ["security-mobile", 390, 844],
  ] as const) {
    const path = `docs/screenshots/${name}.png`;
    expect(readme).toContain(path);
    const png = new Uint8Array(await Bun.file(path).arrayBuffer());
    expect(Array.from(png.subarray(0, 8))).toEqual([137, 80, 78, 71, 13, 10, 26, 10]);
    const dimensions = new DataView(png.buffer, png.byteOffset, png.byteLength);
    expect(dimensions.getUint32(16)).toBe(width);
    expect(dimensions.getUint32(20)).toBeGreaterThanOrEqual(height);
  }
});

test("README documents the lockdown helper, modes, preserved paths, and layout", async () => {
  const readme = await Bun.file("README.md").text();

  for (const term of [
    "/usr/local/libexec/basho-lockdown-helper",
    "status",
    "deny-ip",
    "isolate-lan",
    "inspect",
    "rollback",
    "monitor",
    "approve",
    "auto-lockdown",
    "tailscale0",
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
    "22",
    "src/security/",
    "src/routes/security.tsx",
    "src/templates/security.tsx",
  ]) {
    expect(readme).toContain(term);
  }

  // Port 22 must be described as excluded from scanner discovery, not merely mentioned.
  expect(readme).toMatch(/port\s+22|:22\b.*exclud|exclud.*\b22\b/i);

  // "bun test" belongs to the script list, so anchor it to the Available Scripts section.
  const scriptsIndex = readme.indexOf("Available Scripts");
  expect(scriptsIndex).toBeGreaterThanOrEqual(0);
  const afterScripts = readme.slice(scriptsIndex);
  const architectureIndex = afterScripts.indexOf("## Architecture");
  const scriptsSection =
    architectureIndex === -1 ? afterScripts : afterScripts.slice(0, architectureIndex);
  expect(scriptsSection).toContain("bun test");
});

test("README accurately documents unset BASHO_AUTH_TOKEN behavior and UFW prerequisites", async () => {
  const readme = await Bun.file("README.md").text();

  // Unset BASHO_AUTH_TOKEN leaves /security reads open to peers reaching BASHO_HOST
  // while mutations remain direct loopback-only without proxy headers.
  expect(readme).not.toContain(
    "Operator bearer/login token required for remote reads and mutations on `/security`",
  );
  expect(readme).toMatch(/BASHO_AUTH_TOKEN`?\s+is unset.*reads are open/i);
  expect(readme).toMatch(/bind(?:ing)?\s+`?BASHO_HOST`?\s+to\s+`?127\.0\.0\.1`?/i);

  // Helper UFW prerequisites, existing-rule verification wording, and exact-arg sudoers rule.
  for (const term of [
    "ufw allow in on tailscale0",
    "ufw allow 41641/udp",
    "lan_policy=missing",
    "/usr/local/libexec/basho-lockdown-helper status,",
  ]) {
    expect(readme).toContain(term);
  }
  expect(readme).not.toContain('/usr/local/libexec/basho-lockdown-helper status ""');
  expect(readme).toMatch(/refuse.*modify protected paths/i);
  expect(readme).toMatch(/verifies.*allow rules already exist rather than adding them/i);
});

function pngChunks(bytes: Uint8Array): { type: string; data: Uint8Array }[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunks: { type: string; data: Uint8Array }[] = [];
  let offset = 8;
  while (offset + 12 <= bytes.byteLength) {
    const length = view.getUint32(offset);
    const type = Buffer.from(bytes.subarray(offset + 4, offset + 8)).toString("latin1");
    const start = offset + 8;
    const end = start + length;
    if (end + 4 > bytes.byteLength) break;
    chunks.push({ type, data: bytes.subarray(start, end) });
    if (type === "IEND") break;
    offset = end + 4;
  }
  return chunks;
}

function metadataText(chunk: { type: string; data: Uint8Array }): string | null {
  if (chunk.type === "tEXt") return Buffer.from(chunk.data).toString("latin1");
  if (chunk.type !== "iTXt" && chunk.type !== "zTXt") return null;
  const latin1 = Buffer.from(chunk.data).toString("latin1");
  try {
    const payload = inflateSync(chunk.data.subarray(latin1.indexOf("\0") + 1));
    return Buffer.from(payload).toString("latin1");
  } catch {
    return latin1;
  }
}

test("demo screenshot metadata leaks no local paths, secrets, or hostnames", async () => {
  const forbidden = ["/home/", "OPENCODE_API_KEY", "BASHO_AUTH_TOKEN"];
  const machine = hostname();
  if (machine && machine !== "lab-node-01") forbidden.push(machine);

  for (const name of ["security-desktop", "security-mobile"]) {
    const bytes = new Uint8Array(
      await Bun.file(`docs/screenshots/${name}.png`).arrayBuffer(),
    );
    for (const chunk of pngChunks(bytes)) {
      const text = metadataText(chunk);
      if (text === null) continue;
      for (const term of forbidden) expect(text).not.toContain(term);
    }
  }
});
