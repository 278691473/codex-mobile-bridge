package io.github.try2love.codexbridge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;

/** JVM-only regression for ZCode provider routing, authorize URL policy, and begin requests. */
public final class ZCodeAccountProviderTests {
 private static final String INIT_URL="https://zcode.z.ai/api/v1/oauth/cli/init";
 private static int assertions;

 public static void main(String[] args)throws Exception {
  HttpsFixture.install();
  Method policy=ZCodeAccount.class.getDeclaredMethod("officialAuthorizeUrl",String.class,String.class);
  policy.setAccessible(true);
  verifyAuthorizePolicy(policy);
  verifyBegin();
  verifyUnsupportedProviders();
  System.out.println("ZCodeAccountProviderTests assertions="+assertions);
 }

 private static void verifyAuthorizePolicy(Method policy){
  String[] acceptedBigModel={
   "https://bigmodel.cn/login?state=fixture",
   "https://bigmodel.cn:443/login?state=fixture",
   "https://BIGMODEL.CN/login?state=fixture"
  };
  String[] rejectedBigModel={
   "http://bigmodel.cn/login?state=fixture",
   "https://user@bigmodel.cn/login?state=fixture",
   "https://bigmodel.cn/login?state=fixture#fragment",
   "https://bigmodel.cn:8443/login?state=fixture",
   "https://bigmodel.cn/login?",
   "https://api.bigmodel.cn/login?state=fixture",
   "https://bigmodel.cn/login/?state=fixture",
   "https://chat.z.ai/api/oauth/authorize?state=fixture"
  };
  String[] acceptedZai={
   "https://chat.z.ai/api/oauth/authorize?state=fixture",
   "https://chat.z.ai:443/api/oauth/authorize?state=fixture",
   "https://CHAT.Z.AI/api/oauth/authorize?state=fixture"
  };
  String[] rejectedZai={
   "http://chat.z.ai/api/oauth/authorize?state=fixture",
   "https://user@chat.z.ai/api/oauth/authorize?state=fixture",
   "https://chat.z.ai/api/oauth/authorize?state=fixture#fragment",
   "https://chat.z.ai:8443/api/oauth/authorize?state=fixture",
   "https://chat.z.ai/api/oauth/authorize?",
   "https://www.chat.z.ai/api/oauth/authorize?state=fixture",
   "https://chat.z.ai/api/oauth/authorize/?state=fixture",
   "https://bigmodel.cn/login?state=fixture"
  };
  verifyPolicyValues(policy,"bigmodel",acceptedBigModel,true);
  verifyPolicyValues(policy,"bigmodel",rejectedBigModel,false);
  verifyPolicyValues(policy,"zai",acceptedZai,true);
  verifyPolicyValues(policy,"zai",rejectedZai,false);
  check(!invokePolicy(policy,"other",acceptedZai[0]),"unsupported provider has no authorize origin");
  check(!invokePolicy(policy,null,acceptedBigModel[0]),"null provider has no authorize origin");
 }

 private static void verifyPolicyValues(Method policy,String provider,String[] values,boolean expected){
  for(String value:values)
   check(invokePolicy(policy,provider,value)==expected,provider+" policy for "+value);
 }

 private static boolean invokePolicy(Method policy,String provider,String value){
  try{return (Boolean)policy.invoke(null,provider,value);}
  catch(ReflectiveOperationException failed){throw new AssertionError("officialAuthorizeUrl reflection failed",failed);}
 }

 private static void verifyBegin(){
  verifyBegin("bigmodel","https://bigmodel.cn/login?state=fixture","flow-bigmodel");
  verifyBegin("zai","https://chat.z.ai/api/oauth/authorize?state=fixture","flow-zai");
  verifyBegin("bigmodel","https://chat.z.ai/api/oauth/authorize?state=fixture",null);
  verifyBegin("zai","https://bigmodel.cn/login?state=fixture",null);
 }

 private static void verifyBegin(String provider,String authorizeUrl,String expectedFlowId){
  HttpsFixture.prepare(response(authorizeUrl,expectedFlowId==null?"flow-rejected":expectedFlowId));
  ZCodeAccount.Flow flow=ZCodeAccount.begin(provider);
  MockConnection request=HttpsFixture.last();
  check(HttpsFixture.requestCount()==1,provider+" begin makes one request");
  check(request!=null,provider+" begin uses intercepted HTTPS");
  check(INIT_URL.equals(request.getURL().toString()),provider+" begin targets CLI init");
  check("POST".equals(request.getRequestMethod()),provider+" begin uses POST");
  check(("{\"provider\":\""+provider+"\"}").equals(request.body()),provider+" POST body is provider JSON");
  check("application/json; charset=UTF-8".equals(request.getRequestProperty("Content-Type")),provider+" POST is JSON");
  check("application/json".equals(request.getRequestProperty("Accept")),provider+" requests JSON");
  check("no-store".equals(request.getRequestProperty("Cache-Control")),provider+" bypasses caches");
  String authorization=request.getRequestProperty("Authorization");
  check(authorization!=null&&authorization.matches("Bearer [0-9a-f]{64}"),provider+" sends separate bearer token");
  if(expectedFlowId==null){
   check(flow==null,provider+" rejects another provider's authorize_url");
  }else{
   check(flow!=null,provider+" accepts its authorize_url");
   if(flow==null)return;
   check(authorizeUrl.equals(flow.authorizeUrl),provider+" preserves authorize URL");
   check(expectedFlowId.equals(flow.flowId),provider+" preserves flow id");
   check(flow.expiresAt==2000000000L,provider+" preserves expiry");
   check(flow.pollIntervalSeconds==5,provider+" preserves poll interval");
  }
 }

 private static void verifyUnsupportedProviders(){
  HttpsFixture.prepare(null);
  expectIllegalArgument(()->ZCodeAccount.begin("openai"),"unsupported provider is rejected before networking");
  check(HttpsFixture.requestCount()==0,"unsupported provider makes no request");

  HttpsFixture.prepare(null);
  expectIllegalArgument(()->ZCodeAccount.begin((String)null),"null provider is rejected before networking");
  check(HttpsFixture.requestCount()==0,"null provider makes no request");
 }

 private static String response(String authorizeUrl,String flowId){
  return "{\"code\":0,\"data\":{\"authorize_url\":\""+authorizeUrl
   +"\",\"flow_id\":\""+flowId+"\",\"expires_at\":2000000000,\"poll_interval_sec\":5}}";
 }

 private static void expectIllegalArgument(Runnable action,String message){
  boolean rejected=false;
  try{action.run();}
  catch(IllegalArgumentException expected){rejected=true;}
  catch(Throwable unexpected){throw new AssertionError(message+": wrong exception",unexpected);}
  check(rejected,message);
 }

 private static void check(boolean condition,String message){
  assertions++;
  if(!condition)throw new AssertionError(message);
 }

 private static final class HttpsFixture {
  private static String nextBody;
  private static MockConnection last;
  private static int requestCount;

  static void install(){
   URL.setURLStreamHandlerFactory(protocol->"https".equalsIgnoreCase(protocol)?new Handler():null);
  }

  static void prepare(String body){
   nextBody=body;
   last=null;
   requestCount=0;
  }

  static MockConnection last(){return last;}
  static int requestCount(){return requestCount;}

  private static final class Handler extends URLStreamHandler {
   protected URLConnection openConnection(URL url)throws IOException{
    MockConnection connection=new MockConnection(url,nextBody);
    nextBody=null;
    last=connection;
    requestCount++;
    return connection;
   }
  }
 }

 private static final class MockConnection extends HttpURLConnection {
  private final byte[] response;
  private final ByteArrayOutputStream requestBody=new ByteArrayOutputStream();

  MockConnection(URL url,String responseBody){
   super(url);
   response=responseBody==null?null:responseBody.getBytes(StandardCharsets.UTF_8);
  }

  public void connect(){}
  public void disconnect(){}
  public boolean usingProxy(){return false;}

  public OutputStream getOutputStream(){return requestBody;}

  public int getResponseCode(){return response==null?503:200;}

  public long getContentLengthLong(){return response==null?-1L:response.length;}

  public InputStream getInputStream()throws IOException{
   if(response==null)throw new IOException("unexpected HTTPS request");
   return new ByteArrayInputStream(response);
  }

  String body(){return new String(requestBody.toByteArray(),StandardCharsets.UTF_8);}
 }
}
