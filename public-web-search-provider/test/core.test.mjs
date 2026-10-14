import assert from "node:assert/strict";
import test from "node:test";
import { PublicWebProvider, PublicWebError, validateRequest, buildInvocation, PROTOCOL } from "../src/core.mjs";

const options = { python: "/usr/bin/python3", cwd: "/tmp", stateDir: "/tmp/ttg-search-state",
                  indexDb: "/tmp/ttg-public-web-index.sqlite" };
const output = (extra = {}) => JSON.stringify({
  query: "SQLite FTS5", status: "LOCAL_MATCH",
  result_truth: "LOCAL_INDEXED_NOT_LIVE_VERIFIED",
  network_attempted: false,
  results: [{ url: "https://www.sqlite.org/fts5.html", title: "SQLite FTS5",
              status: "LOCAL_INDEXED", license: "public-domain" }], ...extra });
const mk = (runner) => new PublicWebProvider({ ...options, runner });
test("only recognized commands and fields are admitted", () => {
  for (const request of [
    null, [], {operation:"exec"}, {operation:"search",query:""},
    {operation:"search",query:"word", limit:500},
    {operation:"search",query:"word",shell:true},
    {operation:"search",query:"hello\nworld"},
    {operation:"search",query:"word",scope:"admin"},
    {operation:"search",query:"word",scope:"wikipedia",offline:true},
    {operation:"read",url:"file:///etc/shadow"},
    {operation:"read",url:"http://example.org/"},
    {operation:"read",url:"https://admin:pass@example.org/"},
    {operation:"read",url:"https://example.org:8443/"},
  ]) assert.throws(() => validateRequest(request), PublicWebError);
});
test("search arguments include local-first, no preview, no paid route", () => {
  const request = validateRequest({operation:"search",query:"SQLite FTS5",limit:5});
  const args = buildInvocation(request,options.indexDb);
  assert.deepEqual(args.slice(0,6),["-I","-B","-m","ttg_search","search","SQLite FTS5"]);
  assert.ok(args.includes("--no-preview-fallback"));
  assert.deepEqual(args.slice(-2),["--index-db",options.indexDb]);
  assert.ok(!args.includes("--brave-api"));
  assert.ok(!args.includes("--preview-fallback"));
});
test("read URL handed to validated owned page reader", () => {
  assert.deepEqual(buildInvocation(validateRequest({operation:"read",url:"https://example.com/"})),
    ["-I","-B","-m","ttg_search","read","https://example.com/"]);
});
test("local-only search routes without payment and does not declare canonical truth", async () => {
  const provider=mk(async(args) => {
    assert.ok(args.includes("--offline"));
    return { status:0, stdout:output() };
  });
  const value=await provider.command({operation:"search",query:"SQLite FTS5",offline:true});
  assert.equal(value.source_class,"owned_public_index_noncanonical");
  assert.equal(value.canonical_evidence,false);
  assert.equal(value.browser_replacement,false);
  assert.equal(value.budget_zmw,0);
  assert.equal(value.results[0].status,"LOCAL_INDEXED");
});
test("live result is discovered, not page-verified", async () => {
  const provider=mk(async () => ({
     status:0,stdout:output({results:[{url:"https://example.org/",status:"DISCOVERED"}],
                            result_truth:"DISCOVERED_NOT_PAGE_VERIFIED", network_attempted:true})}));
  const value=await provider.command({operation:"search",query:"SQLite FTS5"});
  assert.equal(value.result_truth,"DISCOVERED_NOT_PAGE_VERIFIED");
  assert.equal(value.canonical_evidence,false);
});
test("exit 2 with empty results remains an observable empty result", async () => {
  const provider=mk(async () => ({status:2,stdout:output({results:[]})}));
  assert.equal((await provider.command({operation:"search",query:"x"})).results.length,0);
});
test("search cannot report paid requests", async () => {
  const provider=mk(async () => ({status:0,stdout:output({paid_requests:1})}));
  await assert.rejects(provider.command({operation:"search",query:"x"}),e=>e.code==="search_contract_violation");
});
test("engine failures are typed and do not echo private input", async () => {
  const provider=mk(async () => ({status:1,stdout:"private query"}));
  await assert.rejects(provider.command({operation:"search",query:"private query"}),
    e=>e.code==="search_engine_error" && !e.message.includes("private"));
});
test("too many hits are a contract violation", async () => {
  const result=JSON.stringify({results:Array(11).fill({url:"https://example.org"})});
  const provider=mk(async () => ({status:0,stdout:result}));
  await assert.rejects(provider.command({operation:"search",query:"x",limit:10}),
    e=>e.code==="search_contract_violation");
});
test("read does not grant trusted workspace evidence", async () => {
  const provider=mk(async()=>({status:0,stdout:JSON.stringify({
    status:"READABLE",url:"https://example.com/",text:"Example Domain"})}));
  const value=await provider.command({operation:"read",url:"https://example.com/"});
  assert.equal(value.canonical_evidence,false);
  assert.equal(value.source_class,"untrusted_public_html");
});
test("health checks exact engine version", async () => {
  const good=mk(async()=>({status:0,stdout:"ttg-internet-search 0.7.0a2 (standalone candidate)\n"}));
  const value=await good.command({operation:"health"});
  assert.equal(value.protocol,PROTOCOL);
  const bad=mk(async()=>({status:0,stdout:"ttg-internet-search 0.6.0a1 (old)\n"}));
  await assert.rejects(bad.command({operation:"health"}),e=>e.code==="search_version_mismatch");
});
test("absolute configured interpreter, index and state required", () => {
  assert.throws(()=>new PublicWebProvider({...options, python:"python3"}),PublicWebError);
  assert.throws(()=>new PublicWebProvider({...options,indexDb:"../../not-sure"}),PublicWebError);
  assert.throws(()=>new PublicWebProvider({...options,timeoutMs:120000}),PublicWebError);
});
test("explicit scoped providers are read-only and limited", () => {
  const wiki=buildInvocation(validateRequest({operation:"search",query:"Zambia",scope:"wikipedia"}),null);
  assert.ok(wiki.includes("--wikipedia"));
  assert.ok(!wiki.includes("--mwmbl-noncommercial"));
});
