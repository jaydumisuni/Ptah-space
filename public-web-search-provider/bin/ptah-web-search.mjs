import { PublicWebProvider, PublicWebError } from "../src/core.mjs";

function parse(argv) {
  const action=argv.shift();
  if (action === "health" && argv.length===0) return {operation:"health"};
  if (action === "read" && argv.length===1) return {operation:"read",url:argv[0]};
  if (action !== "search" || !argv.length) throw new PublicWebError("invalid_cli_usage");
  const query=argv.shift();
  const request={operation:"search",query};
  while (argv.length) {
    const flag=argv.shift();
    if (flag==="--offline") request.offline=true;
    else if (flag==="--fresh") request.require_fresh=true;
    else if (flag==="--limit" && argv.length) request.limit=Number(argv.shift());
    else if (flag==="--scope" && argv.length) request.scope=argv.shift();
    else throw new PublicWebError("invalid_cli_flag");
  }
  return request;
}
async function main() {
  try {
    const input=parse(process.argv.slice(2));
    const provider=new PublicWebProvider({
      python:process.env.PTAH_PUBLIC_WEB_PYTHON,
      cwd:process.env.PTAH_PUBLIC_WEB_HOME,
      stateDir:process.env.PTAH_PUBLIC_WEB_STATE_DIR,
      indexDb:process.env.PTAH_PUBLIC_WEB_INDEX_DB || undefined,
    });
    const result=await provider.command(input);
    process.stdout.write(JSON.stringify(result,null,2)+"\n");
    if (result.status==="OFFLINE_NO_LOCAL_MATCH" ||
        result.status==="OFFLINE_NO_FRESH_RESULTS" ||
        result.status==="LIVE_UNAVAILABLE" ||
        (result.results && result.results.length===0)) process.exitCode=2;
  } catch(error) {
    process.stderr.write((error instanceof PublicWebError ? error.code : "internal_error")+"\n");
    process.exitCode=2;
  }
}
await main();
