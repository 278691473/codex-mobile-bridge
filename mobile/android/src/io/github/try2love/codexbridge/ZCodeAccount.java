package io.github.try2love.codexbridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONArray;
import org.json.JSONObject;

/** Encrypted ZCode account plus the official BigModel/Z.ai CLI OAuth flow. */
final class ZCodeAccount {
 private static final String PREFS="bridge-zcode-account",ITEM="jwt",ALIAS="codex-bridge-zcode-account-v1";
 private static final String API_ROOT="https://zcode.z.ai/api/v1";
 private static final String INIT_URL=API_ROOT+"/oauth/cli/init",DEVICE_URL=API_ROOT+"/remote/device";
 private static final int MAX_BODY=1024*1024,CONNECT_TIMEOUT=10000,READ_TIMEOUT=15000;
 private static final long TOTAL_TIMEOUT=TimeUnit.SECONDS.toNanos(30);
 private static final SecureRandom RANDOM=new SecureRandom();

 static final class Flow {
  final String authorizeUrl,flowId;
  final long expiresAt;
  final int pollIntervalSeconds;
  private final String pollToken;
  private Flow(String authorizeUrl,String flowId,long expiresAt,int pollIntervalSeconds,String pollToken){
   this.authorizeUrl=authorizeUrl;this.flowId=flowId;this.expiresAt=expiresAt;
   this.pollIntervalSeconds=pollIntervalSeconds;this.pollToken=pollToken;
  }
 }

 private static SharedPreferences prefs(Context context){return context.getSharedPreferences(PREFS,0);}
 private static SecretKey key()throws Exception {
  KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
  SecretKey key=(SecretKey)store.getKey(ALIAS,null);if(key!=null)return key;
  KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
  generator.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
   .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
   .setKeySize(256).build());
  return generator.generateKey();
 }

 static String load(Context context){
  String encoded=prefs(context).getString(ITEM,null);if(encoded==null)return null;
  try{
   byte[] bytes=Base64.decode(encoded,Base64.NO_WRAP);
   if(bytes.length<29||bytes.length>24576)return null;
   Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
   cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,bytes,0,12));
   String jwt=new String(cipher.doFinal(bytes,12,bytes.length-12),StandardCharsets.UTF_8);
   return validToken(jwt)?jwt:null;
  }catch(Exception invalid){return null;}
 }

 static void save(Context context,String jwt){
  if(!validToken(jwt))throw new IllegalArgumentException("智谱登录凭据无效");
  try{
   Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key());
   byte[] iv=cipher.getIV(),encrypted=cipher.doFinal(jwt.getBytes(StandardCharsets.UTF_8));
   byte[] combined=new byte[iv.length+encrypted.length];
   System.arraycopy(iv,0,combined,0,iv.length);System.arraycopy(encrypted,0,combined,iv.length,encrypted.length);
   if(!prefs(context).edit().putString(ITEM,Base64.encodeToString(combined,Base64.NO_WRAP)).commit())
    throw new IllegalStateException("无法安全保存智谱登录");
  }catch(IllegalStateException failed){throw failed;}
  catch(Exception failed){throw new IllegalStateException("无法安全保存智谱登录");}
 }

 static void clear(Context context){
  if(!prefs(context).edit().remove(ITEM).commit())throw new IllegalStateException("无法清除智谱登录");
 }

 static Flow begin(String provider){
  if(!"bigmodel".equals(provider)&&!"zai".equals(provider))throw new IllegalArgumentException("不支持的智谱账号类型");
  String pollToken=randomHex(32);
  JSONObject envelope=request("POST",INIT_URL,pollToken,"{\"provider\":\""+provider+"\"}");
  if(envelope==null)return null;
  JSONObject data=envelope.optJSONObject("data");if(data==null)return null;
  String authorizeUrl=text(data,"authorize_url",8192),flowId=text(data,"flow_id",256);
  Number expiresValue=number(data,"expires_at"),intervalValue=number(data,"poll_interval_sec");
  if(!officialAuthorizeUrl(provider,authorizeUrl)||!validFlowId(flowId)||expiresValue==null||intervalValue==null)return null;
  double expires=expiresValue.doubleValue(),interval=intervalValue.doubleValue();
  if(expires<1||expires>253402300799d||expires!=Math.rint(expires)
   ||interval<1||interval>3600||interval!=Math.rint(interval))return null;
  return new Flow(authorizeUrl,flowId,(long)expires,(int)interval,pollToken);
 }

 static String poll(Flow flow){
  if(flow==null||!validFlowId(flow.flowId)||!validToken(flow.pollToken))return null;
  if(System.currentTimeMillis()/1000L>=flow.expiresAt)return null;
  String endpoint=API_ROOT+"/oauth/cli/poll/"+Uri.encode(flow.flowId,"-._~");
  JSONObject envelope=request("GET",endpoint,flow.pollToken,null);
  if(envelope==null)return null;
  JSONObject data=envelope.optJSONObject("data");
  if(data==null||!"ready".equals(data.optString("status","")))return null;
  String jwt=text(data,"token",16384),userId="";
  JSONObject user=data.optJSONObject("user");
  if(user!=null)userId=text(user,"user_id",256);
  return validToken(jwt)&&!userId.isEmpty()?jwt:null;
 }

 static void verifyDevice(String jwt,String sid,String mid){
  if(!validToken(jwt))throw new IllegalStateException("请先登录智谱账号");
  if(!validDeviceId(sid)||!validDeviceId(mid))throw new IllegalStateException("智谱电脑信息无效");
  JSONObject envelope=request("GET",DEVICE_URL,jwt,null);
  JSONArray devices=envelope==null?null:envelope.optJSONArray("data");
  if(devices==null)throw new IllegalStateException("暂时无法核验智谱电脑，请稍后重试");
  for(int i=0;i<devices.length();i++){
   JSONObject device=devices.optJSONObject(i);
   if(device!=null&&sid.equals(device.optString("device_sid",""))&&mid.equals(device.optString("device_mid","")))return;
  }
  throw new IllegalStateException("此智谱账号未绑定该电脑");
 }

 private static JSONObject request(String method,String endpoint,String bearer,String json){
  if(!endpoint.startsWith(API_ROOT+"/")||!validToken(bearer))return null;
  HttpURLConnection connection=null;
  try{
   byte[] body=json==null?null:json.getBytes(StandardCharsets.UTF_8);
   connection=(HttpURLConnection)new URL(endpoint).openConnection();
   connection.setRequestMethod(method);connection.setInstanceFollowRedirects(false);connection.setUseCaches(false);
   connection.setConnectTimeout(CONNECT_TIMEOUT);connection.setReadTimeout(READ_TIMEOUT);
   connection.setRequestProperty("Accept","application/json");connection.setRequestProperty("Accept-Encoding","identity");
   connection.setRequestProperty("Authorization","Bearer "+bearer);connection.setRequestProperty("Cache-Control","no-store");
   connection.setRequestProperty("User-Agent","CodexBridge-Android/1");
   if(body!=null){
    connection.setDoOutput(true);connection.setFixedLengthStreamingMode(body.length);
    connection.setRequestProperty("Content-Type","application/json; charset=UTF-8");
    try(OutputStream out=connection.getOutputStream()){out.write(body);}
   }
   int status=connection.getResponseCode();
   if(status<200||status>=300||connection.getContentLengthLong()>MAX_BODY)return null;
   long deadline=System.nanoTime()+TOTAL_TIMEOUT;
   ByteArrayOutputStream out=new ByteArrayOutputStream();
   try(InputStream in=connection.getInputStream()){
    byte[] buffer=new byte[8192];int count;
    while((count=in.read(buffer))!=-1){
     if(out.size()+count>MAX_BODY||System.nanoTime()>deadline)return null;
     out.write(buffer,0,count);
    }
   }
   JSONObject envelope=new JSONObject(out.toString("UTF-8"));
   Number code=number(envelope,"code");
   return code!=null&&code.longValue()==0?envelope:null;
  }catch(Exception unavailable){return null;}
  finally{if(connection!=null)connection.disconnect();}
 }

 private static String text(JSONObject value,String name,int max){
  Object raw=value.opt(name);if(!(raw instanceof String))return "";
  String text=(String)raw;if(text.isEmpty()||text.length()>max)return "";
  for(int i=0;i<text.length();i++){char c=text.charAt(i);if(c<0x20||c==0x7f)return "";}
  return text;
 }
 private static Number number(JSONObject value,String name){
  Object raw=value.opt(name);return raw instanceof Number?(Number)raw:null;
 }
 private static boolean validToken(String value){
  if(value==null||value.length()<8||value.length()>16384)return false;
  for(int i=0;i<value.length();i++){char c=value.charAt(i);if(c<0x21||c>0x7e)return false;}
  return true;
 }
 private static boolean validDeviceId(String value){return value!=null&&value.matches("[A-Za-z0-9_-]{1,160}");}
 private static boolean validFlowId(String value){return value!=null&&value.matches("[A-Za-z0-9._~-]{1,256}");}
 private static boolean officialAuthorizeUrl(String provider,String value){
  String host,path;
  if("bigmodel".equals(provider)){host="bigmodel.cn";path="/login";}
  else if("zai".equals(provider)){host="chat.z.ai";path="/api/oauth/authorize";}
  else return false;
  try{
   URI url=new URI(value);
   return "https".equalsIgnoreCase(url.getScheme())&&host.equalsIgnoreCase(url.getHost())
    &&url.getRawUserInfo()==null&&(url.getPort()==-1||url.getPort()==443)
    &&path.equals(url.getRawPath())&&url.getRawFragment()==null
    &&url.getRawQuery()!=null&&!url.getRawQuery().isEmpty();
  }catch(Exception invalid){return false;}
 }
 private static String randomHex(int bytes){
  byte[] random=new byte[bytes];RANDOM.nextBytes(random);
  char[] hex=new char[bytes*2],digits="0123456789abcdef".toCharArray();
  for(int i=0;i<random.length;i++){int value=random[i]&0xff;hex[i*2]=digits[value>>>4];hex[i*2+1]=digits[value&15];}
  return new String(hex);
 }
}
