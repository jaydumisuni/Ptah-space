#!/usr/bin/env node
/** Ptah workspace's default browser tool selector.
 *
 * Routing applies to this Ptah-owned workspace entry only; it does not enroll
 * a production Ptah Node or take over Oracle's shared browser session.
 * Never discover/use OS Chrome. Delegates exclusively to Ptah's A11 operator.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export function routeWorkspaceBrowser(argv) {
  let tokens=[...argv];
  if (tokens[0]==="browser") tokens=tokens.slice(1);
  if (tokens[0] && /^https?:\/\//i.test(tokens[0])) tokens=["read",...tokens];
  const [verb,url,...options]=tokens;
  if (verb!=="read" || !url || options.some(x=>x!=="--screenshot"&&x!=="--headed")) {
    throw new Error("unsupported_workspace_action: usage: ptah_workspace.mjs [browser] read https://example.com/ [--screenshot] [--headed]");
  }
  const parsed=new URL(url);
  if (!["https:","http:"].includes(parsed.protocol)||parsed.username||parsed.password) {
    throw new Error("invalid_workspace_url: only public-facing HTTP(S) URLs without embedded credentials");
  }
  // The caller explicitly chose --headed. No extra Ptah permission
  // environment variable may override the admitted caller's tool choice.
  return {command:"ptah-owned-a11",action:"read",url:parsed.toString(),options};
}

async function main(argv) {
  const route=routeWorkspaceBrowser(argv);
  const entry=fileURLToPath(new URL("./ptah_workspace_browser.mjs",import.meta.url));
  // There is deliberately no Oracle Browser or system Chrome fallback.
  const child=spawn(process.execPath,[entry,route.action,route.url,...route.options],{
    stdio:"inherit",env:process.env
  });
  const code=await new Promise((resolve,reject)=>{
    child.on("error",reject);
    child.on("exit",value=>resolve(value??2));
  });
  process.exitCode=code;
}
if (process.argv[1] && fileURLToPath(import.meta.url)===process.argv[1]) {
  main(process.argv.slice(2)).catch(error=>{
    process.stderr.write(JSON.stringify({status:"WORKSPACE_BROWSER_UNAVAILABLE",
      error:error.message,route:"ptah-owned-a11",fallbackToOracle:false})+"\n");
    process.exitCode=2;
  });
}
