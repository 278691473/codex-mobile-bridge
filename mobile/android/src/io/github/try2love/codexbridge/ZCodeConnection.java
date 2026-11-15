package io.github.try2love.codexbridge;

import android.content.Context;
import android.content.SharedPreferences;
import java.net.InetAddress;
import java.net.ServerSocket;

/** One saved desktop relay. Its stable local origin preserves the original app's bindings. */
final class ZCodeConnection {
 private static final Object LOCK=new Object();
 private static long generation;
 private static volatile Connection current;
 private static final java.util.concurrent.ExecutorService closer=java.util.concurrent.Executors.newSingleThreadExecutor(r->{Thread thread=new Thread(r,"zcode-close");thread.setDaemon(true);return thread;});
 private static final class Connection {
  final ZCodeTransport transport;final ZCodeLocalGateway gateway;final String origin,cookie;
  Connection(ZCodeTransport transport,ZCodeLocalGateway gateway,String origin){this.transport=transport;this.gateway=gateway;this.origin=origin;this.cookie=gateway.capabilityCookie();}
 }
 private static SharedPreferences prefs(Context c){return c.getSharedPreferences("bridge-zcode",0);}
 static String origin(Context c){int port=prefs(c).getInt("port",0);return port>0?"http://127.0.0.1:"+port:"";}
 static boolean manages(Context c,String address){return !address.isEmpty()&&address.equals(origin(c));}
 static String cookie(String address){Connection snapshot=current;return snapshot!=null&&snapshot.origin.equals(address)?snapshot.cookie:"";}
 static void save(Context c,ZCodePairing target)throws Exception {
  synchronized(LOCK){
  SharedPreferences p=prefs(c);String sid=p.getString("sid",""),mid=p.getString("mid","");
  if(!sid.isEmpty()&&(!sid.equals(target.sid)||!mid.equals(target.mid)))throw new Exception("请先移除已保存的智谱电脑，再连接另一台");
  int port=p.getInt("port",0);
  if(port==0)try(ServerSocket reserve=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){port=reserve.getLocalPort();}
  if(!p.edit().putString("sid",target.sid).putString("mid",target.mid).putString("name",target.name).putInt("port",port).commit())throw new Exception("无法保存智谱电脑连接");generation++;
  }
 }
 static String ensure(Context c)throws Exception {
  String base=origin(c);if(base.isEmpty())throw new Exception("请先添加智谱配对链接");
  final Connection snapshot;final long ticket;
  synchronized(LOCK){snapshot=current;ticket=generation;}
  if(snapshot!=null&&snapshot.origin.equals(base)){
   if(snapshot.transport.isKicked())throw new Exception("连接已被其他终端接管");
   if(!snapshot.transport.isConnected())snapshot.transport.connect();
   synchronized(LOCK){if(current!=snapshot||ticket!=generation)throw new Exception("连接已取消");}return base;
  }
  String jwt=ZCodeAccount.load(c);if(jwt==null||jwt.isEmpty())throw new Exception("请先登录智谱账号");
  SharedPreferences p=prefs(c);ZCodeAccount.verifyDevice(jwt,p.getString("sid",""),p.getString("mid",""));
  ZCodeTransport next=new ZCodeTransport(jwt,p.getString("sid",""),p.getString("mid",""));
  ZCodeLocalGateway local=null;
  try{next.connect();local=new ZCodeLocalGateway(next,p.getInt("port",0));String actual=local.start();if(!base.equals(actual))throw new Exception("本地中继端口发生变化，请重新连接");Connection connected=new Connection(next,local,base);synchronized(LOCK){if(ticket!=generation||current!=snapshot)throw new Exception("连接已取消");current=connected;}return base;}
  catch(Exception failed){if(local!=null)local.close();next.close();throw failed;}
 }
 private static void retire(Connection old){if(old!=null){old.gateway.close();closer.execute(old.transport::close);}}
 static void close(){Connection old;synchronized(LOCK){old=current;current=null;generation++;}retire(old);}
 static void forget(Context c){Connection old;synchronized(LOCK){old=current;current=null;generation++;prefs(c).edit().clear().commit();}retire(old);}
}
