'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.resolve(__dirname,'../android/src/io/github/try2love/codexbridge/MainActivity.java'),'utf8');

function method(signature){
 const start=source.indexOf(signature);assert.ok(start>=0,'missing '+signature);
 const open=source.indexOf('{',start);let depth=1,end=open+1;
 for(;depth&&end<source.length;end++){if(source[end]==='{')depth++;if(source[end]==='}')depth--;}
 assert.equal(depth,0,'unclosed '+signature);return source.slice(open+1,end-1);
}
// Execute the production login bodies, translating only Java syntax. Android,
// encrypted storage and OAuth are fixtures; no network, device or Keystore access.
function javascript(body){
 return body.replace(/\b(?:final\s+)?(?:int|long|String|ProgressDialog|ZCodeAccount\.Flow)\s+(\w+)\s*=/g,'let $1=')
  .replace(/catch\(Exception\s+(\w+)\)/g,'catch($1)').replace(/new Exception\(/g,'new Error(')
  .replace(/\b(\d+)L\b/g,'$1').replace(/\b(\w+)\.isEmpty\(\)/g,'($1.length===0)').replace(/->/g,'=>');
}
const entry=javascript(method('void loginZCode(ZCodePairing target)'));
const login=javascript(method('void loginZCode(ZCodePairing target,String provider)'));

function harness(options={}){
 const events=[],workers=[],ui=[],dialogs=[],progresses=[];
 const target={sid:'test-sid',mid:'test-mid',name:'Test computer'};
 class ProgressDialog {
  constructor(){progresses.push(this);}
  setMessage(value){this.message=value;}
  setCancelable(){}
  setOnCancelListener(listener){this.cancel=listener;}
  show(){}
  dismiss(){this.dismissed=true;}
 }
 class Dialog {
  constructor(){this.buttons={};}
  setTitle(value){this.title=value;return this;}
  setMessage(value){this.message=value;return this;}
  setPositiveButton(label,click){this.buttons.positive={label,click};return this;}
  setNeutralButton(label,click){this.buttons.neutral={label,click};return this;}
  setNegativeButton(label,click){this.buttons.negative={label,click};return this;}
  setOnCancelListener(listener){this.cancel=listener;return this;}
  show(){dialogs.push(this);return this;}
 }
 class Intent {static ACTION_VIEW='view';constructor(action,url){this.action=action;this.url=url;}}
 const context={
  relayLoginGeneration:0,relayWorker:{execute:task=>workers.push(task)},runOnUiThread:task=>ui.push(task),
  isFinishing:()=>!!options.finishing,isDestroyed:()=>!!options.destroyed,getApplicationContext:()=>({}),L:value=>value,
  ProgressDialog,AlertDialog:{Builder:Dialog},Intent,Uri:{parse:value=>value},
  System:{currentTimeMillis:()=>1000000},Thread:{sleep:()=>assert.fail('unexpected polling delay')},
  ZCodeAccount:{
   load:()=>{events.push(['load']);return options.jwt===undefined?null:options.jwt;},
   begin:provider=>{events.push(['begin',provider]);return {authorizeUrl:'https://example.invalid/authorize',expiresAt:2000,pollIntervalSeconds:1};},
   poll:()=>{events.push(['poll']);return 'synthetic-new-jwt';},
   verifyDevice:(jwt,sid,mid)=>{events.push(['verify',jwt,sid,mid]);if(options.rejectDevice)throw new Error('account mismatch');},
   save:(_,jwt)=>events.push(['save-jwt',jwt])
  },
  ZCodeConnection:{save:(_,value)=>events.push(['save-target',value]),close:()=>events.push(['close']),origin:()=> 'http://127.0.0.1:43123'},
  prefs:{edit:()=>({putString:()=>({apply(){}})})},connect:url=>events.push(['connect',url]),
  startActivity:intent=>events.push(['browser',intent.url]),message:text=>events.push(['message',text])
 };
 vm.createContext(context);
 vm.runInContext('function startLogin(target){'+entry+'}\nfunction loginZCode(target,provider){'+login+'}',context);
 function drain(queue){while(queue.length)queue.shift()();}
 function flush(){while(workers.length||ui.length){drain(workers);drain(ui);}}
 return {context,target,events,dialogs,progresses,flush,workers,ui,start:()=>context.startLogin(target),of:kind=>events.filter(event=>event[0]===kind)};
}
function assertSavedAfterVerification(h,jwt){
 assert.deepEqual(h.of('verify'),[['verify',jwt,h.target.sid,h.target.mid]]);
 assert.deepEqual(h.of('save-target'),[['save-target',h.target]]);
 assert.deepEqual(h.of('save-jwt'),[['save-jwt',jwt]]);
 const kinds=h.events.map(event=>event[0]);
 assert.ok(kinds.indexOf('verify')<kinds.indexOf('save-target'));
 assert.ok(kinds.indexOf('verify')<kinds.indexOf('save-jwt'));
 assert.equal(h.of('connect').length,1);
}

for(const jwt of [null,''])test('无 JWT '+JSON.stringify(jwt)+'：后台读取后等待选择，不默认发起 BigModel OAuth',()=>{
 const h=harness({jwt});h.start();assert.equal(h.of('load').length,0);assert.equal(h.workers.length,1);h.flush();
 assert.equal(h.of('load').length,1);assert.equal(h.dialogs.length,1);assert.equal(h.of('begin').length,0);
 assert.equal(h.of('verify').length,0);assert.equal(h.of('save-target').length,0);assert.equal(h.of('save-jwt').length,0);
 assert.match(h.dialogs[0].message,/绑定这台电脑的同一账号/);assert.equal(h.progresses[0].dismissed,true);
});

for(const [button,label,provider] of [['positive','Z.ai（国际）','zai'],['neutral','BigModel（国内）','bigmodel']]){
 test(label+' 选择调用对应 provider，核验设备后才保存',()=>{
  const h=harness();h.start();h.flush();const choice=h.dialogs[0].buttons[button];assert.equal(choice.label,label);
  choice.click();assert.equal(h.of('begin').length,0);h.flush();
  assert.deepEqual(h.of('begin'),[['begin',provider]]);assert.equal(h.of('browser').length,1);
  assertSavedAfterVerification(h,'synthetic-new-jwt');
 });
}

test('已有 JWT 直接复用，不显示平台选择、不开始 OAuth，仍先核验设备',()=>{
 const h=harness({jwt:'synthetic-cached-jwt'});h.start();h.flush();
 assert.equal(h.dialogs.length,0);assert.equal(h.of('begin').length,0);assert.equal(h.of('browser').length,0);
 assertSavedAfterVerification(h,'synthetic-cached-jwt');
});

for(const cancel of ['negative','back'])test(cancel+' 取消不发起 OAuth、不保存，旧选项回调也失效',()=>{
 const h=harness();h.start();h.flush();const dialog=h.dialogs[0],attempt=h.context.relayLoginGeneration;
 if(cancel==='negative')dialog.buttons.negative.click();else dialog.cancel();
 assert.ok(h.context.relayLoginGeneration>attempt);dialog.buttons.positive.click();dialog.buttons.neutral.click();h.flush();
 assert.equal(h.of('begin').length,0);assert.equal(h.of('save-target').length,0);assert.equal(h.of('save-jwt').length,0);
});

test('选择前取消进度提示，排队的 JWT 读取和选择均失效',()=>{
 const h=harness();h.start();h.progresses[0].cancel();h.flush();
 assert.equal(h.dialogs.length,0);assert.equal(h.of('begin').length,0);assert.equal(h.of('save-target').length,0);assert.equal(h.of('save-jwt').length,0);
});

for(const jwt of [null,'synthetic-cached-jwt'])test('设备核验失败不保存：'+(jwt?'已有 JWT':'新登录'),()=>{
 const h=harness({jwt,rejectDevice:true});h.start();h.flush();if(!jwt){h.dialogs[0].buttons.positive.click();h.flush();}
 assert.equal(h.of('verify').length,1);assert.equal(h.of('save-target').length,0);assert.equal(h.of('save-jwt').length,0);
 assert.equal(h.of('connect').length,0);assert.equal(h.of('message').length,1);
});

test('Activity 已销毁时不弹平台选择、不保存',()=>{
 const h=harness({destroyed:true});h.start();h.flush();
 assert.equal(h.dialogs.length,0);assert.equal(h.of('begin').length,0);assert.equal(h.of('save-target').length,0);assert.equal(h.of('save-jwt').length,0);
});
