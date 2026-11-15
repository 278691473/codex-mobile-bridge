package io.github.try2love.codexbridge;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Concurrency regression for the real ZCodeConnection helper and minimal stubs. */
public final class ZCodeConnectionConcurrencyTests {
 private static final long FAST_MS=750;
 private static final int PORT=45678;
 private static final String BASE="http://127.0.0.1:"+PORT;

 public static void main(String[] args)throws Exception {
  testBlockedConnectDoesNotHoldLifecycleLock();
  testGatewayDetachesBeforeAsyncTransportClose();
  testTargetConflictPrecedesAccountWrite();
  System.out.println("ZCodeConnection concurrency tests passed");
 }

 private static void testBlockedConnectDoesNotHoldLifecycleLock()throws Exception {
  Context context=context("sid-a","mid-a",PORT);
  ZCodeAccount.reset("jwt-a.b.c");
  ZCodeTransport.reset();
  ZCodeLocalGateway.reset();
  ZCodeTransport.blockConnect=true;

  ExecutorService executor=Executors.newSingleThreadExecutor();
  Future<String> pending=executor.submit(()->ZCodeConnection.ensure(context));
  check(ZCodeTransport.connectEntered.await(3,TimeUnit.SECONDS),"ensure did not enter blocked connect");
  startWatchdog(ZCodeTransport.connectRelease);

  timed("cookie",()->check(ZCodeConnection.cookie(BASE).isEmpty(),"inactive cookie was visible"));
  timed("close",ZCodeConnection::close);
  timed("forget",()->ZCodeConnection.forget(context));

  // Restore only the immutable connection identity so the released stale ensure
  // reaches the generation commit guard instead of failing on a missing port.
  context.prefs("bridge-zcode").edit().putString("sid","sid-a").putString("mid","mid-a").putInt("port",PORT).commit();
  ZCodeTransport.connectRelease.countDown();
  expectCancelled(pending);
  executor.shutdownNow();

  check(ZCodeLocalGateway.created.get()==1,"stale ensure did not create its candidate gateway");
  check(ZCodeLocalGateway.closed.get()==1,"stale candidate gateway was not closed");
  check(ZCodeTransport.closeCalls.get()==1,"stale candidate transport was not closed");
  check(ZCodeConnection.cookie(BASE).isEmpty(),"stale candidate was committed");
 }

 private static void testGatewayDetachesBeforeAsyncTransportClose()throws Exception {
  Context context=context("sid-a","mid-a",PORT);
  ZCodeAccount.reset("jwt-a.b.c");
  ZCodeTransport.reset();
  ZCodeLocalGateway.reset();

  check(BASE.equals(ZCodeConnection.ensure(context)),"initial ensure returned wrong origin");
  ZCodeTransport.blockNextClose.set(true);
  String initial=ZCodeConnection.cookie(BASE);
  check(!initial.isEmpty(),"initial capability was unavailable");

  timed("committed close",ZCodeConnection::close);
  check(ZCodeConnection.cookie(BASE).isEmpty(),"current snapshot survived close");
  check(ZCodeLocalGateway.closed.get()==1,"gateway close was not released synchronously");
  check(ZCodeTransport.closeEntered.await(2,TimeUnit.SECONDS),"transport did not enter async close");

  // The old transport close is intentionally still blocked. A replacement
  // connection must be able to attach after the local gateway is released.
  check(BASE.equals(ZCodeConnection.ensure(context)),"replacement ensure failed");
  check(!ZCodeConnection.cookie(BASE).isEmpty(),"replacement capability was unavailable");
  check(ZCodeLocalGateway.created.get()==2,"replacement gateway was not created");

  ZCodeTransport.closeRelease.countDown();
  ZCodeConnection.close();
  waitFor(()->ZCodeTransport.closeCalls.get()>=2,"new transport close was not queued");
 }

 private static void testTargetConflictPrecedesAccountWrite()throws Exception {
  Context context=context("sid-a","mid-a",PORT);
  ZCodeAccount.reset("jwt-a.b.c");
  ZCodeAccount.saveCalls.set(0);
  ZCodePairing different=new ZCodePairing("sid-b","mid-b","Other desktop");

  boolean rejected=saveInMainActivityOrder(context,different,"jwt-b.c.d");
  check(rejected,"different sid/mid was not rejected");
  check(ZCodeAccount.saveCalls.get()==0,"JWT was changed before target conflict rejection");
  check("jwt-a.b.c".equals(ZCodeAccount.jwt),"stub JWT changed after rejection");
  SharedPreferences prefs=context.prefs("bridge-zcode");
  check("sid-a".equals(prefs.getString("sid",null)),"saved sid changed after rejection");
  check("mid-a".equals(prefs.getString("mid",null)),"saved mid changed after rejection");
 }

 /** Mirrors the current MainActivity order: target preflight, JWT, then close. */
 private static boolean saveInMainActivityOrder(Context context,ZCodePairing target,String jwt) {
  try{
   ZCodeConnection.save(context,target);
   ZCodeAccount.save(context,jwt);
   ZCodeConnection.close();
   return false;
  }catch(Exception expected){
   return true;
  }
 }

 private static Context context(String sid,String mid,int port){
  Context context=new Context();
  context.prefs("bridge-zcode").edit()
   .putString("sid",sid).putString("mid",mid).putInt("port",port).commit();
  return context;
 }

 private static void expectCancelled(Future<String> pending)throws Exception {
  try{
   pending.get(5,TimeUnit.SECONDS);
   throw new AssertionError("cancelled ensure committed");
  }catch(ExecutionException expected){
   Throwable cause=expected.getCause();
   check(cause!=null&&String.valueOf(cause.getMessage()).contains("连接已取消"),"unexpected ensure failure: "+cause);
  }
 }

 private static void timed(String name,Runnable action){
  long started=System.nanoTime();
  action.run();
  long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started);
  check(elapsed<FAST_MS,name+" waited for blocked network IO: "+elapsed+"ms");
 }

 private static void waitFor(Check condition,String message)throws Exception {
  long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
  while(System.nanoTime()<deadline){
   if(condition.ok())return;
   Thread.sleep(10);
  }
  throw new AssertionError(message);
 }

 private static void startWatchdog(CountDownLatch release){
  Thread watchdog=new Thread(()->{
   try{Thread.sleep(1800);}catch(InterruptedException ignored){}
   release.countDown();
  },"test-connect-watchdog");
  watchdog.setDaemon(true);
  watchdog.start();
 }

 private static void check(boolean value,String message){
  if(!value)throw new AssertionError(message);
 }

 private interface Check{boolean ok();}
}
