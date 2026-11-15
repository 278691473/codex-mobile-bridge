package io.github.try2love.codexbridge;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Collections;

/** Reopening a socket is allowed only before sending a new request. */
public final class ZCodeTransportRecoveryTests {
 private static int checks;
 public static void main(String[] args)throws Exception {
  try(Offline transport=new Offline(false)){
   expect(()->transport.request("GET","/api/auth",Collections.emptyMap(),null),"reconnect fixture");
   check(transport.connects==1,"a disconnected new request attempts one connection");
  }
  try(Offline transport=new Offline(false)){
   expect(()->transport.request("PUT","/api/auth",Collections.emptyMap(),null),null);
   expect(()->transport.request("GET","//external.invalid",Collections.emptyMap(),null),null);
   check(transport.connects==0,"invalid requests never start a connection");
  }
  try(Offline transport=new Offline(true)){
   boolean unknown=false;
   try{transport.request("POST","/api/login",Collections.emptyMap(),new byte[]{123,125});}
   catch(ZCodeTransport.RequestUnknownException expected){unknown=true;}
   check(unknown,"a send failure preserves the unknown result");
   check(transport.connects==0,"an in-flight failure never reconnects or replays the request");
  }
  ZCodeTransport closed=new ZCodeTransport("fixture-unused","d_fixture","mid_fixture");
  closed.close();
  expect(()->closed.request("GET","/api/auth",Collections.emptyMap(),null),"ZCode transport is closed");
  ZCodeTransport kicked=new ZCodeTransport("fixture-unused","d_fixture","mid_fixture");
  try{
   Field flag=ZCodeTransport.class.getDeclaredField("kicked");flag.setAccessible(true);flag.setBoolean(kicked,true);
   expect(()->kicked.request("GET","/api/auth",Collections.emptyMap(),null),"ZCode transport was rejected");
  }finally{kicked.close();}
  System.out.println("ZCODE_RECOVERY_PASS "+checks);
 }
 private interface Action {void run()throws IOException;}
 private static void expect(Action action,String message)throws Exception {
  boolean failed=false;
  try{action.run();}catch(IOException expected){failed=true;if(message!=null)check(message.equals(expected.getMessage()),"expected connection failure");}
  check(failed,"request fails without retrying");
 }
 private static void check(boolean condition,String message){checks++;if(!condition)throw new AssertionError(message);}
 private static final class Offline extends ZCodeTransport implements AutoCloseable {
  private final boolean ready;int connects;
  Offline(boolean ready){super("fixture-unused","d_fixture","mid_fixture");this.ready=ready;}
  @Override public boolean isConnected(){return ready;}
  @Override public void connect()throws IOException {connects++;throw new IOException("reconnect fixture");}
 }
}
