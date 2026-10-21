import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile, chmod, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
const server = resolve("src/server.mjs");

function captureLines(child, expected, timeout = 6000) {
  return new Promise((resolvePromise, reject) => {
    const output = [];
    let buff = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("server_response_timeout"));
    }, timeout);
    child.stdout.on("data", chunk => {
      buff += chunk.toString("utf8");
      for (;;) {
        const i = buff.indexOf("\n");
        if (i<0) break;
        const line = buff.slice(0,i);
        buff = buff.slice(i+1);
        output.push(JSON.parse(line));
        if (output.length>=expected) {
          clearTimeout(timer);
          resolvePromise(output);
          return;
        }
      }
    });
    child.on("error", e => {clearTimeout(timer);reject(e);});
  });
}

test("newline protocol retains IDs, isolates bad commands and never invokes a shell", async () => {
  const temp = await mkdtemp(join(tmpdir(), "ptah-web-provider-test-"));
  const python = join(temp, "python");
  await writeFile(python, "#!/usr/bin/env node\n" +
    "const a=process.argv.slice(2);\n" +
    "if(a.includes('version')) process.stdout.write('ttg-internet-search 0.7.0a2 (standalone candidate)\\n');\n" +
    "else if(a.includes('search')) process.stdout.write(JSON.stringify({status:'LOCAL_MATCH',results:[{status:'LOCAL_INDEXED',url:'https://example.org/'}],paid_requests:0})+'\\n');\n" +
    "else process.stdout.write(JSON.stringify({status:'READABLE',url:'https://example.com/',text:'Example Domain'})+'\\n');\n");
  await chmod(python,0o700);
  const child=spawn(process.execPath,[server],{
    cwd:resolve("."),
    env: { PATH:process.env.PATH, HOME:temp,
           PTAH_PUBLIC_WEB_PYTHON:python, PTAH_PUBLIC_WEB_HOME:temp,
           PTAH_PUBLIC_WEB_STATE_DIR:temp },
    stdio:["pipe","pipe","pipe"]});
  try{
    const pending=captureLines(child,4);
    child.stdin.write('{"id":"h","operation":"health"}\n');
    child.stdin.write('{"id":"bad","operation":"exec","command":"sh -c id"}\n');
    child.stdin.write('{"id":"s","operation":"search","query":"SQLite FTS5","offline":true}\n');
    child.stdin.write('{"id":"r","operation":"read","url":"https://example.com/"}\n');
    const responses=await pending;
    assert.deepEqual(responses.map(x=>x.id),["h","bad","s","r"]);
    assert.equal(responses[0].result.status,"READY");
    assert.equal(responses[1].ok,false);
    assert.equal(responses[1].error.code,"unsupported_operation");
    assert.equal(responses[2].result.canonical_evidence,false);
    assert.equal(responses[3].result.source_class,"untrusted_public_html");
    for(const result of responses){
      assert.ok(!JSON.stringify(result).includes("sh -c"));
    }
  }finally{
    child.kill("SIGTERM");
    await rm(temp,{recursive:true,force:true});
  }
});

test("invalid provider config fails closed before reading requests", async () => {
  const child=spawn(process.execPath,[server],{
    env:{ PATH:process.env.PATH,HOME:process.env.HOME??"/tmp" },
    cwd:resolve("."),
    stdio:["pipe","pipe","pipe"]});
  const rc=await new Promise(resolve=>child.once("close",resolve));
  assert.equal(rc,2);
});
