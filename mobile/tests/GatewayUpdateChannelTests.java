package io.github.try2love.codexbridge;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** A fork app must not accept the official APK through an older gateway. */
public final class GatewayUpdateChannelTests {
 public static void main(String[] args)throws Exception {
  JSONObject body=new JSONObject().put("supported",true).put("release",JSONObject.NULL);
  HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
  server.createContext("/api/mobile/update",exchange->{
   byte[] bytes=body.toString().getBytes(StandardCharsets.UTF_8);
   exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);exchange.close();
  });
  server.start();
  try{
   String base="http://127.0.0.1:"+server.getAddress().getPort();
   GatewayUpdate update=new GatewayUpdate(base,()->"fixture=session");
   for(String repo:new String[]{"", "https://github.com/try2love/codex-mobile-bridge"}){
    body.put("repository",repo);
    try{update.check("2.2.1-preview.1");throw new AssertionError("foreign update channel accepted");}catch(IOException expected){}
   }
   body.put("repository",MobileRelease.REPO);
   if(update.check("2.2.1-preview.1")!=null)throw new AssertionError("unexpected release");
   System.out.println("Gateway update channel: missing/official rejected; fork accepted");
  }finally{server.stop(0);}
 }
}
