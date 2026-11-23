// Season 6 720p x265 GD: source-bound navigation and network witness, no downloads.
// User completes Pahe's hCaptcha. We do not manipulate or bypass the challenge.
const {chromium}=require('/home/kratos/projects/Ptah-space/browser-provider/node_modules/playwright');
const fs=require('fs');
const path='/home/kratos/projects/Ptah-space/.workspace/snowfall-navigation/';
const source='https://pahe.plus/86jB';
const allowedFileHosts=[/^(?:[a-z0-9-]+\.)*gdflix\.io$/i,/^pixeldrain\.(?:com|net)$/i,/^(?:drive|docs)\.google\.com$/i,/^1fichier\.com$/i];
let captured=null, opened=false;
const log=(...args)=>console.log(new Date().toISOString(),...args);
function verifyUrl(value){try{const x=new URL(value);return x.protocol==='https:'&&allowedFileHosts.some(r=>r.test(x.hostname))}catch{return false}}
(async()=>{
 const browser=await chromium.launch({headless:false,executablePath:'/usr/bin/google-chrome',args:['--disable-dev-shm-usage']});
 const context=await browser.newContext({acceptDownloads:false,viewport:{width:1080,height:800}});
 context.on('page',p=>p.on('download',d=>{log('DOWNLOAD_BLOCKED',d.suggestedFilename());d.cancel()}));
 let blocked=0;
 await context.route('**/*',async route=>{
  const u=new URL(route.request().url());
  const suspect=(u.hostname==='pahe.plus'&&/^\/[a-z0-9]{9,}\/[a-f0-9]{8,}\.js$/i.test(u.pathname))||/iatserver\.com|auctionr\.org|usherjusticefalling\.com|freelygreatestscammer\.com|s0-greate\.net/i.test(u.hostname);
  if(suspect){blocked++;return route.abort()}
  return route.continue();
 });
 const page=await context.newPage();
 const deliver=async url=>{
  if(!verifyUrl(url)){log('NONFILE_DESTINATION',String(url).slice(0,400));return}
  if(opened)return;opened=true;
  captured=url;
  fs.writeFileSync(path+'season6-gd-confirmed-destination.json',JSON.stringify({season:6,source,destination:url,verifiedAt:new Date().toISOString()},null,2));
  const p=await context.newPage();
  log('OPEN_FINAL',url);
  await p.goto(url,{waitUntil:'domcontentloaded',timeout:35000}).catch(e=>log('FINAL_NAV_ERROR',e.message.slice(0,130)));
  log('FINAL_PAGE',p.url(),await p.title().catch(()=>''));
 };
 page.on('response',async response=>{
  try{
   const u=new URL(response.url());
   if(u.hostname!=='pahe.plus'||u.pathname!=='/links/go')return;
   log('GO_LINK_RESPONSE',response.status());
   const data=await response.json().catch(()=>null);
   if(data?.url){log('GO_LINK_TARGET',data.url);await deliver(data.url)}
   else log('GO_LINK_NO_TARGET',JSON.stringify(data).slice(0,300));
  }catch(e){log('GO_LINK_ERROR',e.message.slice(0,140))}
 });
 page.on('framenavigated',async frame=>{
  if(frame!==page.mainFrame())return;
  const url=page.url();log('PAGE_NAV',url.slice(0,320));
  if(verifyUrl(url))await deliver(url);
 });
 page.on('load',async()=>{
  try{
   const banner=await page.locator('#go-link').count();
   if(!banner)return;
   log('BANNER_REACHED','go-link-form-present');
   const t=await page.locator('a.get-link').getAttribute('href').catch(()=>null);
   if(t&&verifyUrl(t))await deliver(t);
   // The site's own countdown and Ajax handler initiate the request. We do not forge or bypass any gates.
  }catch(e){log('BANNER_CHECK_ERROR',e.message.slice(0,150))}
 });
 await page.goto(source,{waitUntil:'domcontentloaded',timeout:30000});
 log('READY','captcha_present='+Boolean(await page.locator('#captchaShortlink').count()),'ad_scripts_blocked='+blocked);
 // After the user genuinely solves hCaptcha, use the page's enabled Continue button.
 // No CAPTCHA interaction or token manipulation. Subsequent countdown and AJAX remain site-controlled.
 let clickedVerifiedContinue=false;
 const continuationPoll=setInterval(async()=>{
  if(clickedVerifiedContinue || opened || page.isClosed())return;
  try{
   if(!new URL(page.url()).hostname.endsWith('pahe.plus'))return;
   const realButton=page.locator('#link-view #invisibleCaptchaShortlink');
   if(await realButton.count()===1 && await realButton.isEnabled()){
    clickedVerifiedContinue=true;
    log('HUMAN_VERIFICATION_ACCEPTED','real Continue enabled');
    await realButton.click({timeout:10000});
    log('REAL_CONTINUE_CLICKED');
   }
  }catch(e){log('REAL_CONTINUE_ERROR',e.message.slice(0,180))}
 },900);
 browser.on('disconnected',()=>clearInterval(continuationPoll));
 process.on('SIGTERM',()=>browser.close().finally(()=>process.exit(0)));
 browser.on('disconnected',()=>process.exit(0));
})().catch(e=>{log('FATAL',e.message);process.exit(1)});
