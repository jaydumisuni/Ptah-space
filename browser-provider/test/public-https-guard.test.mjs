import test from "node:test";
import assert from "node:assert/strict";
import { connect } from "node:net";
import { PlaywrightBackend } from "../src/playwright_backend.mjs";
import { once } from "node:events";
import {
  isPublicIPv4, publicHttpsHost, authorizedPublicIp, startPublicHttpsProxy
} from "../src/public_https_guard.mjs";

test("public HTTPS proxy rejects all known private, special and documentation IPs",()=>{
  for (const ip of ["127.0.0.1","10.0.0.1","0.1.2.3","169.254.169.254",
    "172.16.2.1","172.31.255.255","192.168.1.1","100.64.0.1",
    "198.18.0.1","192.0.2.1","198.51.100.8","203.0.113.3",
    "224.0.0.1","255.255.255.255","::1","::ffff:127.0.0.1"])
    assert.equal(isPublicIPv4(ip),false,ip);
  for(const ip of ["1.1.1.1","8.8.8.8","104.16.120.1"])
    assert.equal(isPublicIPv4(ip),true,ip);
});
test("host policy prohibits IP literals, special local domains and non-443 ports",()=>{
  for(const host of ["127.0.0.1:443","[::1]:443","localhost:443",
    "metadata.google.internal:443","portal.local:443","router.home.arpa:443",
    "example.com:8443","example.com:80","a..b.com:443","a-.com:443",
    "example.com:443@127.0.0.1:443"])
    assert.equal(publicHttpsHost(host),null,host);
  assert.equal(publicHttpsHost("Example.com:443"),"example.com");
});
test("each DNS lookup rejects all-private, mixed and empty results, pins public", async()=>{
  const bad=[
    [{address:"127.0.0.1"}],[{address:"8.8.8.8"},{address:"10.2.2.2"}],[],
    [{address:"::1"}]
  ];
  for(const answer of bad)
    assert.equal(await authorizedPublicIp("example.com:443",async()=>answer),null);
  assert.deepEqual(await authorizedPublicIp("example.com:443",async()=>[
    {address:"8.8.8.8"},{address:"1.1.1.1"}
  ]),{host:"example.com",address:"8.8.8.8"});
  let called=false;
  assert.equal(await authorizedPublicIp("localhost:443",async()=>{
    called=true;return [{address:"8.8.8.8"}]
  }),null);
  assert.equal(called,false);
});
test("actual local listener refuses CONNECT to internal IP before any outbound socket",async()=>{
  const proxy=await startPublicHttpsProxy({resolveDns:async()=>[{address:"127.0.0.1"}]});
  try {
    const target=new URL(proxy.url);
    const client=connect({host:target.hostname,port:Number(target.port)});
    await once(client,"connect");
    client.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
    const response=await Promise.race([
      once(client,"data").then(([data])=>data.toString("utf8")),
      new Promise((_,reject)=>setTimeout(()=>reject(Error("timed out")),2500))
    ]);
    assert.match(response,/403 Forbidden/);
    client.destroy();
  } finally {await proxy.close()}
});


test("Ptah browser backend fails closed if public policy lacks owned proxy", async()=>{
  const browser=new PlaywrightBackend();
  const fake={kind:"ephemeral",browser:{newContext:()=>{throw Error("MUST_NOT_CREATE")}}};
  await assert.rejects(browser.createContext(fake,{
    networkPolicy:{publicHttpsEgress:true},contextOptions:{serviceWorkers:"block",acceptDownloads:false}
  }),{code:"public_egress_proxy_required"});
  await assert.rejects(browser.createContext(fake,{
    networkPolicy:{publicHttpsEgress:true},contextOptions:{
      serviceWorkers:"allow",acceptDownloads:false,
      proxy:{server:"http://127.0.0.1:9001",bypass:"<-loopback"}
    }
  }),{code:"public_egress_browser_policy_required"});
});

test("CONNECT reset during pending DNS does not terminate proxy process",async()=>{
  let reachedDns;
  const dnsStarted=new Promise(resolve=>{reachedDns=resolve});
  const proxy=await startPublicHttpsProxy({
    resolveDns:()=>{
      reachedDns();
      return new Promise(resolve=>setTimeout(()=>resolve([{address:"127.0.0.1"}]),120));
    }
  });
  try {
    const dest=new URL(proxy.url);
    const conn=connect(Number(dest.port),"127.0.0.1");
    await once(conn,"connect");
    conn.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
    await Promise.race([dnsStarted,
      new Promise((_,reject)=>setTimeout(()=>reject(Error("DNS_HANDLER_NOT_REACHED")),900))
    ]);
    conn.on("error",()=>{});
    conn.resetAndDestroy();
    await new Promise(resolve=>setTimeout(resolve,180));
    const stillAlive=connect(Number(dest.port),"127.0.0.1");
    await once(stillAlive,"connect");
    stillAlive.destroy();
  } finally {await proxy.close()}
});
