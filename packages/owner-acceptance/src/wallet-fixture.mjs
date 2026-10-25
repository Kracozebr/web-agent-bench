import { createHash } from "node:crypto";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const digest = (value) => createHash("sha256").update(String(value)).digest("hex");

export async function installWalletFixture(page, {
  chainId = 8453,
  invalidSignature = false,
  messageMutation,
} = {}) {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const audit = { providerInjected: false, signingRequests: 0, lastMessageSha256: null, addressSha256: digest(account.address.toLowerCase()) };
  let lastProof;

  await page.exposeFunction("__oidSignMessage", async (message) => {
    if (typeof message !== "string" || !message.length) throw new Error("The SIWE message was empty");
    audit.signingRequests += 1;
    let signedMessage = message;
    if (messageMutation === "wrong-domain") signedMessage = signedMessage.replace(/^127\.0\.0\.1:3000 wants/m, "attacker.example.invalid wants");
    if (messageMutation === "wrong-uri") signedMessage = signedMessage.replace(/^URI: http:\/\/127\.0\.0\.1:3000$/m, "URI: https://attacker.example.invalid");
    if (messageMutation === "wrong-chain") signedMessage = signedMessage.replace(/^Chain ID: 8453$/m, "Chain ID: 1");
    if (messageMutation === "not-yet-valid") signedMessage = signedMessage.replace(/^Issued At: .+$/m, `Issued At: ${new Date(Date.now() + 120_000).toISOString()}`);
    if (messageMutation === "expired") signedMessage = signedMessage.replace(/^Expiration Time: .+$/m, `Expiration Time: ${new Date(Date.now() - 120_000).toISOString()}`);
    audit.lastMessageSha256 = digest(signedMessage);
    if (invalidSignature) return "0xdeadbeef";
    const signature = await account.signMessage({ message: signedMessage });
    lastProof = { message: signedMessage, signature };
    return signature;
  });
  await page.addInitScript(({ address, selectedChainId }) => {
    Object.defineProperty(window, "ethereum", {
      configurable: true,
      value: {
        isMetaMask: true,
        request: async ({ method, params = [] }) => {
          if (method === "eth_requestAccounts" || method === "eth_accounts") return [address];
          if (method === "eth_chainId") return `0x${selectedChainId.toString(16)}`;
          if (method === "personal_sign") {
            const message = Array.isArray(params) ? params[0] : undefined;
            return window.__oidSignMessage(message);
          }
          throw new Error(`Unsupported local wallet method: ${method}`);
        },
      },
    });
  }, { address: account.address, selectedChainId: chainId });
  audit.providerInjected = true;
  return { account, audit, proof: () => lastProof ? { ...lastProof } : undefined };
}
