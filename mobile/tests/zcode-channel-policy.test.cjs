'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../..');
const source=fs.readFileSync(path.join(root,'mobile/android/src/io/github/try2love/codexbridge/MainActivity.java'),'utf8').replace(/\r\n/g,'\n');

function method(text,signature){
 const start=text.indexOf(signature);assert.ok(start>=0,'missing '+signature);
 const open=text.indexOf('{',start);let depth=1,end=open+1;
 for(;depth;end++){if(text[end]==='{')depth++;if(text[end]==='}')depth--;}
 return text.slice(open+1,end-1);
}
function assignment(text,name){
 const match=text.match(new RegExp(name+'=([^;]+);'));
 assert.ok(match,'missing assignment '+name);return match[1];
}

const remember=method(source,'void rememberConnection()');
const dataExpression=assignment(remember,'JSONObject data');
const enrollmentExpression=assignment(remember,'GatewayChannels.Enrollment enrollment');

function evaluatePolicy(zcode,authenticated,trustedDevice){
 let descriptorCalls=0,enrollCalls=0,routeReads=0;
 const data={kind:'descriptor'},enrollment={kind:'enrollment'};
 const auth={optBoolean:key=>key==='authenticated'?authenticated:key==='trustedDevice'?trustedDevice:false,optJSONObject:()=>{routeReads++;return {routes:true};}};
 const ConnectionDiscovery={descriptor:(receivedAuth,receivedBinding)=>{descriptorCalls++;assert.equal(receivedAuth,auth);assert.equal(receivedBinding,'binding-token');return data;}};
 const GatewayChannels={enroll:(...args)=>{enrollCalls++;assert.equal(args.length,6);return enrollment;}};
 const EventClient={tokenValue:value=>'token:'+value};
 const dataValue=new Function('zcode','auth','binding','ConnectionDiscovery','return ('+dataExpression+');')(zcode,auth,'binding-token',ConnectionDiscovery);
 const enrollmentValue=new Function('zcode','auth','prefs','address','name','binding','GatewayChannels','EventClient','return ('+enrollmentExpression+');')(zcode,auth,{},'http://127.0.0.1:43123','computer','binding-token',GatewayChannels,EventClient);
 return {dataValue,enrollmentValue,descriptorCalls,enrollCalls,routeReads,data,enrollment};
}

test('智谱连接跳过 descriptor 和 GatewayChannels enrollment，普通可信网关仍执行两者',()=>{
 const zcode=evaluatePolicy(true,true,true);
 assert.equal(zcode.dataValue,null);assert.equal(zcode.enrollmentValue,null);assert.equal(zcode.descriptorCalls,0);assert.equal(zcode.enrollCalls,0);assert.equal(zcode.routeReads,0);
 const ordinary=evaluatePolicy(false,true,true);
 assert.equal(ordinary.dataValue,ordinary.data);assert.equal(ordinary.enrollmentValue,ordinary.enrollment);assert.equal(ordinary.descriptorCalls,1);assert.equal(ordinary.enrollCalls,1);assert.equal(ordinary.routeReads,1);
 const untrusted=evaluatePolicy(false,false,true);
 assert.equal(untrusted.dataValue,untrusted.data);assert.equal(untrusted.enrollmentValue,null);assert.equal(untrusted.enrollCalls,0);
});

test('退出和移除智谱都清除 loopback localcap cookie',()=>{
 const helper=method(source,'void clearZCodeCookie(String base)').replace(/->/g,' => ');
 let singleton;
 class CookieManagerFixture{
  constructor(){this.setCookies=[];this.flushes=0;}
  setCookie(url,value,callback){this.setCookies.push([url,value]);callback(true);}
  flush(){this.flushes++;}
 }
 singleton=new CookieManagerFixture();
 const CookieManager={getInstance:()=>singleton};
 const clear=new Function('CookieManager','return function clearZCodeCookie(base){'+helper+'}')(CookieManager);
 const javaString=value=>Object.assign(new String(value),{isEmpty(){return value.length===0;}});
 clear(javaString('http://127.0.0.1:43123'));
 assert.deepEqual(singleton.setCookies,[['http://127.0.0.1:43123/','localcap=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict']]);
 assert.equal(singleton.flushes,1);
 clear(javaString(''));
 assert.equal(singleton.setCookies.length,1);assert.equal(singleton.flushes,1);
 const logout=method(source,'void forgetZCode()');
 const remove=method(source,'void confirmRemove(String target)');
 assert.match(logout,/if\(!base\.isEmpty\(\)\)clearZCodeCookie\(base\)/);
 assert.match(remove,/final boolean zcode=ZCodeConnection\.manages\(this,target\)/);
 assert.match(remove,/if\(zcode\)clearZCodeCookie\(target\)/);
});