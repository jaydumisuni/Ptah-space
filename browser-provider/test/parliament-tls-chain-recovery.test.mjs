import test from "node:test";
import assert from "node:assert/strict";
import { PlaywrightBackend, needsParliamentChainRecovery } from "../src/playwright_backend.mjs";

const invalid = { message: "page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://www.parliament.gov.zm/" };

function harness({ warmStatus = 200, warmUrl = "https://parliament.gov.zm/appsuite/", failWarm = false } = {}) {
  const events=[];
  let first=true;
  const warm={
    async goto(url, options) {
      events.push(["warm",url,options.waitUntil]);
      if(failWarm) throw new Error("net::ERR_CERT_AUTHORITY_INVALID");
      return { status:()=>warmStatus };
    },
    url:()=>warmUrl,
    async close() {events.push(["warm-closed"]);},
  };
  const page={
    context:()=>({newPage: async()=>{events.push(["newPage"]);return warm;}}),
    async goto(url, options) {
      events.push(["goto",url,options.waitUntil]);
      if(first){first=false;throw invalid;}
      return {status:()=>200, allHeaders:async()=>({})};
    },
    url:()=>"https://www.parliament.gov.zm/members-of-parliament",
  };
  return {page,events};
}

test("narrow Parliament issuer gap predicate cannot affect other websites",()=>{
  assert.equal(needsParliamentChainRecovery("https://www.parliament.gov.zm/",invalid),true);
  assert.equal(needsParliamentChainRecovery("https://www.parliament.gov.zm/members-of-parliament",invalid),true);
  for(const url of ["https://parliament.gov.zm/", "http://www.parliament.gov.zm/",
    "https://www.parliament.gov.zm.evil.test/", "https://user:pass@www.parliament.gov.zm/",
    "https://www.parliament.gov.zm:4443/", "https://self-signed.badssl.com/"]){
    assert.equal(needsParliamentChainRecovery(url,invalid),false,url);
  }
  assert.equal(needsParliamentChainRecovery("https://www.parliament.gov.zm/",{message:"timeout"}),false);
});

test("only the missing intermediate is recovered, original HTTPS path preserved",async()=>{
  const {page,events}=harness();
  const result=await new PlaywrightBackend().navigate({page}, {
    url:"https://www.parliament.gov.zm/members-of-parliament",timeoutMs:20000});
  assert.equal(result.status,200);
  assert.equal(result.committedUrl,"https://www.parliament.gov.zm/members-of-parliament");
  assert.equal(result.evidence.parliamentIssuerChainRecovered,true);
  assert.deepEqual(events.map(row=>row[0]),["goto","newPage","warm","warm-closed","goto"]);
  assert.equal(events[2][1],"https://parliament.gov.zm/");
  assert.equal(events[4][1],"https://www.parliament.gov.zm/members-of-parliament");
});

test("invalid official chain never results in an insecure attempt or substituted login page",async()=>{
  const {page,events}=harness({warmStatus:403});
  await assert.rejects(new PlaywrightBackend().navigate({page},{
    url:"https://www.parliament.gov.zm/",timeoutMs:20000
  }),{code:"parliament_chain_source_invalid"});
  assert.deepEqual(events.map(row=>row[0]),["goto","newPage","warm","warm-closed"]);
});
test("failed sibling TLS verification fails closed with no second navigation",async()=>{
  const {page,events}=harness({failWarm:true});
  await assert.rejects(new PlaywrightBackend().navigate({page},{
    url:"https://www.parliament.gov.zm/",timeoutMs:20000
  }),/ERR_CERT_AUTHORITY_INVALID/);
  assert.deepEqual(events.map(row=>row[0]),["goto","newPage","warm","warm-closed"]);
});
test("Ptah context refuses TLS verification bypass requests",async()=>{
  await assert.rejects(new PlaywrightBackend().createContext({},{
    contextOptions:{ignoreHTTPSErrors:true}
  }),{code:"tls_verification_bypass_forbidden"});
});

test("Ptah rejects explicit insecure launch arguments", {
  skip: process.env.PTAH_PLAYWRIGHT_PHYSICAL !== "1",
}, async () => {
  for(const flag of ["--ignore-certificate-errors","--ignore-certificate-errors-spki-list=ABCD",
                       "--allow-insecure-localhost","--disable-web-security"]){
    await assert.rejects(new PlaywrightBackend().launchProcess({
      profileMode:"ephemeral",launchOptions:{args:[flag],headless:true}
    }),{code:"tls_verification_bypass_forbidden"},flag);
  }
});

test("Persistent Ptah profile cannot opt out of HTTPS verification", {
  skip: process.env.PTAH_PLAYWRIGHT_PHYSICAL !== "1",
}, async () => {
  await assert.rejects(new PlaywrightBackend().launchProcess({
    profileMode: "persistent_exclusive",
    userDataDir: "/tmp/ptah-tls-rejection-must-not-be-created",
    launchOptions: {ignoreHTTPSErrors:true, headless:true}
  }),{code:"tls_verification_bypass_forbidden"});
});
