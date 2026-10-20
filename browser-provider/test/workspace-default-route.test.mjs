import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { routeWorkspaceBrowser } from "../../tools/ptah_workspace.mjs";

const exe=fileURLToPath(new URL("../../tools/ptah_workspace.mjs",import.meta.url));
const run=promisify(execFile);

test("agent workspace browser is routed to Ptah A11, never Oracle",()=>{
  const route=routeWorkspaceBrowser(["browser","read","https://example.com/"]);
  assert.equal(route.command,"ptah-owned-a11");
  assert.equal(route.action,"read");
  assert.equal(route.url,"https://example.com/");
});
test("URL shorthand defaults to owned workspace A11 browser",()=>{
  assert.equal(routeWorkspaceBrowser(["https://example.com/"]).command,"ptah-owned-a11");
});
test("rejects Oracle shared, arbitrary shell, and credentialed URLs",()=>{
  for(const argv of [["oracle","read","https://example.com/"],
                     ["shell","rm","-rf","/"],
                     ["read","file:///etc/passwd"],
                     ["browser","read","https://user:secret@example.com/"]]){
    assert.throws(()=>routeWorkspaceBrowser(argv));
  }
});
test("headed desktop view is caller-selected, without second Ptah permission",()=>{
  const before=process.env.PTAH_WORKSPACE_ALLOW_HEADED;
  delete process.env.PTAH_WORKSPACE_ALLOW_HEADED;
  try{
    const explicit=routeWorkspaceBrowser(["browser","read","https://example.com/","--headed"]);
    assert.ok(explicit.options.includes("--headed"));
    const normal=routeWorkspaceBrowser(["browser","read","https://example.com/"]);
    assert.equal(normal.options.includes("--headed"),false);
  }finally{
    if(before===undefined)delete process.env.PTAH_WORKSPACE_ALLOW_HEADED;
    else process.env.PTAH_WORKSPACE_ALLOW_HEADED=before;
  }
});
test("physical default route opens Ptah Chromium and verifies page",{
  skip:process.env.PTAH_PLAYWRIGHT_PHYSICAL!=="1"
},async()=>{
  const server=createServer((_req,res)=>{
    res.setHeader("Content-Type","text/html");
    res.end("<html><head><title>Ptah Dedicated Workspace</title></head><body><h1>Agent Default Browser</h1></body></html>");
  });
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{
    const {port}=server.address();
    const {stdout,stderr}=await run(process.execPath,
      [exe,"browser","read",`http://127.0.0.1:${port}/`],{
      timeout:30_000,maxBuffer:150_000
    });
    assert.equal(stderr,"");
    const out=JSON.parse(stdout);
    assert.equal(out.browserSource,"ptah_owned_chromium");
    assert.equal(out.oracleBrowserControlUsed,false);
    assert.equal(out.sharesPersonalBrowser,false);
    assert.equal(out.pageStateVerified,true);
    assert.equal(out.title,"Ptah Dedicated Workspace");
  }finally{await new Promise(resolve=>server.close(resolve));}
});
