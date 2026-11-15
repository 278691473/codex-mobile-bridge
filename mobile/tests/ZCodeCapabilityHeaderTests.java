package io.github.try2love.codexbridge;

import android.content.Context;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Local HTTP regression for native ZCode capability headers and exact-origin isolation. */
public final class ZCodeCapabilityHeaderTests {
 private static final String NAME="codex_mobile_session_aaaaaaaaaaaaaaaaaaaaaaaa";
 private static final String TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 private static final String CAPABILITY="fixture-capability";
 private static final Map<HttpServer,RequestRecorder> RECORDERS=new ConcurrentHashMap<>();

 public static void main(String[] args)throws Exception {
  HttpServer exact=server();
  HttpServer ordinary=server();
  HttpServer wrong=server();
  RequestRecorder exactRecorder=RECORDERS.get(exact),ordinaryRecorder=RECORDERS.get(ordinary),wrongRecorder=RECORDERS.get(wrong);
  try{
   String origin=origin(exact);
   Context context=context(exact.getAddress().getPort());
   check(origin.equals(ZCodeConnection.ensure(context)),"fixture connection origin");
   check(CAPABILITY.equals(ZCodeConnection.capabilityToken(origin)),"exact origin capability");
   check(ZCodeConnection.capabilityToken(origin+"/").isEmpty(),"lookalike origin must not receive capability");
   check(ZCodeConnection.capabilityToken(origin(exact).replace("127.0.0.1","localhost")).isEmpty(),"different host spelling must not receive capability");
   check(("localcap="+CAPABILITY).equals(ZCodeConnection.cookie(origin)),"WebView bootstrap capability cookie remains available");

   exactRecorder.reset();
   check(new GatewayProbe().check(origin),"exact loopback probe");
   check(CAPABILITY.equals(exactRecorder.capability),"exact probe capability header");
   check(exactRecorder.cookie==null,"capability probe must not send Cookie");

   ordinaryRecorder.reset();
   check(new GatewayProbe().check(origin(ordinary)),"ordinary gateway probe");
   check(ordinaryRecorder.capability==null,"ordinary gateway must not receive capability");
   check(ordinaryRecorder.cookie==null,"ordinary gateway must not receive Cookie");

   wrongRecorder.reset();
   check(new GatewayProbe().check(origin(wrong)),"different loopback origin probe");
   check(wrongRecorder.capability==null,"wrong origin must not receive capability");
   check(wrongRecorder.cookie==null,"wrong origin probe must not receive Cookie");

   DeviceBinding.Credential credential=new DeviceBinding.Credential(NAME,TOKEN);
   exactRecorder.reset();
   check(Boolean.TRUE.equals(DeviceBinding.verify(origin,credential)),"exact binding verification");
   check(CAPABILITY.equals(exactRecorder.capability),"binding capability header");
   check(credential.cookie().equals(exactRecorder.cookie),"binding sends account Cookie only");
   check(!exactRecorder.cookie.contains("localcap"),"binding Cookie must not contain loopback capability");
   check(origin.equals(GatewayURL.httpOrigin(origin)),"binding canonical loopback origin");

   wrongRecorder.reset();
   check(Boolean.TRUE.equals(DeviceBinding.verify(origin(wrong),credential)),"binding fixture response at other origin");
   check(wrongRecorder.capability==null,"binding must not leak capability to wrong origin");
   check(!wrongRecorder.cookie.contains("localcap"),"wrong origin must not receive capability Cookie");

   System.out.println("ZCode capability header tests passed");
  }finally{
   ZCodeConnection.close();
   exact.stop(0);ordinary.stop(0);wrong.stop(0);
  }
 }

 private static Context context(int port){
  Context context=new Context();
  context.prefs("bridge-zcode").edit().putString("sid","fixture-sid").putString("mid","fixture-mid").putInt("port",port).commit();
  ZCodeAccount.reset("fixture.jwt.value");
  ZCodeTransport.reset();
  ZCodeLocalGateway.reset(CAPABILITY);
  return context;
 }

 private static HttpServer server()throws IOException {
  HttpServer server=HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),0),0);
  RECORDERS.put(server,new RequestRecorder());
  server.createContext("/api/auth",ZCodeCapabilityHeaderTests::handle);
  server.start();
  return server;
 }

 private static void handle(HttpExchange exchange)throws IOException {
  RequestRecorder recorder=RECORDERS.get(exchange.getHttpContext().getServer());
  recorder.capture(exchange);
  String cookie=exchange.getRequestHeaders().getFirst("Cookie");
  String body="{\"authenticated\":"+(cookie!=null)+",\"passwordless\":true,\"instanceId\":\"fixture\",\"cookieName\":\""+NAME+"\"}";
  byte[] bytes=body.getBytes(StandardCharsets.UTF_8);
  exchange.getResponseHeaders().set("Content-Type","application/json; charset=UTF-8");
  exchange.sendResponseHeaders(200,bytes.length);
  try(OutputStream output=exchange.getResponseBody()){output.write(bytes);}
 }

 private static String origin(HttpServer server){
  return "http://127.0.0.1:"+server.getAddress().getPort();
 }

 private static void check(boolean condition,String message){
  if(!condition)throw new AssertionError(message);
 }

 private static final class RequestRecorder {
  volatile String capability,cookie,origin;
  void reset(){capability=null;cookie=null;origin=null;}
  void capture(HttpExchange exchange){
   capability=exchange.getRequestHeaders().getFirst(ZCodeLocalGateway.CAP_HEADER);
   cookie=exchange.getRequestHeaders().getFirst("Cookie");
   origin=exchange.getRequestHeaders().getFirst("Origin");
  }
 }
}
