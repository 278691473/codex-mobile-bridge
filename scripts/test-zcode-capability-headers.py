#!/usr/bin/env python3
"""Compile the real Android ZCode capability header paths and run them against local HTTP."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = ROOT / ".tmp"
JSON_JAR = TMP_ROOT / "mobile-tools/android-json-0.0.20131108.vaadin1.jar"
JSON_SHA = JSON_JAR.with_suffix(".jar.sha1")

STUBS = {
    "android/content/Context.java": """package android.content;
import java.util.concurrent.ConcurrentHashMap;
public class Context {
 private final ConcurrentHashMap<String,SharedPreferences> PREFS=new ConcurrentHashMap<>();
 public SharedPreferences getSharedPreferences(String name,int mode){return prefs(name);}
 public SharedPreferences prefs(String name){return PREFS.computeIfAbsent(name,key->new MemoryPrefs());}
}
""",
    "android/content/SharedPreferences.java": """package android.content;
public interface SharedPreferences {
 String getString(String key,String fallback);
 int getInt(String key,int fallback);
 Editor edit();
 interface Editor {
  Editor putString(String key,String value);
  Editor putInt(String key,int value);
  Editor clear();
  Editor remove(String key);
  void apply();
  boolean commit();
 }
}
""",
    "android/content/MemoryPrefs.java": """package android.content;
import java.util.concurrent.ConcurrentHashMap;
final class MemoryPrefs implements SharedPreferences {
 private final ConcurrentHashMap<String,Object> values=new ConcurrentHashMap<>();
 public String getString(String key,String fallback){Object value=values.get(key);return value instanceof String?(String)value:fallback;}
 public int getInt(String key,int fallback){Object value=values.get(key);return value instanceof Integer?(Integer)value:fallback;}
 public Editor edit(){return new Editor(){
  public Editor putString(String key,String value){values.put(key,value);return this;}
  public Editor putInt(String key,int value){values.put(key,value);return this;}
  public Editor clear(){values.clear();return this;}
  public Editor remove(String key){values.remove(key);return this;}
  public void apply(){}
  public boolean commit(){return true;}
 };}
}
""",
    "android/os/SystemClock.java": """package android.os;
public final class SystemClock {
 public static long elapsedRealtime(){return System.nanoTime()/1000000L;}
}
""",
    "android/security/keystore/KeyGenParameterSpec.java": """package android.security.keystore;
public final class KeyGenParameterSpec implements java.security.spec.AlgorithmParameterSpec {
 public static final class Builder {
  public Builder(String alias,int purposes){}
  public Builder setBlockModes(String... modes){return this;}
  public Builder setEncryptionPaddings(String... paddings){return this;}
  public Builder setKeySize(int size){return this;}
  public KeyGenParameterSpec build(){return new KeyGenParameterSpec();}
 }
}
""",
    "android/security/keystore/KeyProperties.java": """package android.security.keystore;
public final class KeyProperties {
 public static final String KEY_ALGORITHM_AES="AES";
 public static final int PURPOSE_ENCRYPT=1;
 public static final int PURPOSE_DECRYPT=2;
 public static final String BLOCK_MODE_GCM="GCM";
 public static final String ENCRYPTION_PADDING_NONE="NoPadding";
}
""",
    "android/util/Base64.java": """package android.util;
public final class Base64 {
 public static final int NO_WRAP=2;
 public static String encodeToString(byte[] bytes,int flags){return java.util.Base64.getEncoder().encodeToString(bytes);}
 public static byte[] decode(String value,int flags){return java.util.Base64.getDecoder().decode(value);}
}
""",
    "io/github/try2love/codexbridge/EventClient.java": """package io.github.try2love.codexbridge;
final class EventClient {static final String USER_AGENT="BridgeMobile/fixture";}
""",
    "io/github/try2love/codexbridge/ZCodePairing.java": """package io.github.try2love.codexbridge;
final class ZCodePairing {
 final String sid,mid,name;
 ZCodePairing(String sid,String mid,String name){this.sid=sid;this.mid=mid;this.name=name;}
}
""",
    "io/github/try2love/codexbridge/ZCodeAccount.java": """package io.github.try2love.codexbridge;
import android.content.Context;
final class ZCodeAccount {
 private static String jwt="";
 static void reset(String value){jwt=value;}
 static String load(Context context){return jwt;}
 static void verifyDevice(String value,String sid,String mid)throws Exception{if(value==null||value.isEmpty())throw new Exception("missing jwt");}
}
""",
    "io/github/try2love/codexbridge/ZCodeTransport.java": """package io.github.try2love.codexbridge;
final class ZCodeTransport {
 private boolean connected;
 static void reset(){}
 ZCodeTransport(String jwt,String sid,String mid){}
 void connect()throws Exception{connected=true;}
 boolean isConnected(){return connected;}
 boolean isKicked(){return false;}
 void close(){}
}
""",
    "io/github/try2love/codexbridge/ZCodeLocalGateway.java": """package io.github.try2love.codexbridge;
final class ZCodeLocalGateway {
 static final String CAP_COOKIE="localcap";
 static final String CAP_HEADER="X-ZCode-Local-Cap";
 private static String capability;
 private final int port;
 static void reset(String value){capability=value;}
 ZCodeLocalGateway(ZCodeTransport transport,int port){this.port=port;}
 String start(){return origin();}
 String capabilityCookie(){return CAP_COOKIE+"="+capability;}
 String capabilityToken(){return capability;}
 private String origin(){return "http://127.0.0.1:"+port;}
 void close(){}
}
""",
}


def run(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command,cwd=ROOT,text=True,encoding="utf-8",errors="replace",
                            capture_output=True,timeout=timeout,check=False)
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result


def java_tool(name: str) -> Path | None:
    executable=name+(".exe" if sys.platform=="win32" else "")
    candidates=[]
    for variable in ("JAVA_HOME","JDK_HOME"):
        if value:=os.environ.get(variable):
            candidates.append(Path(value)/"bin"/executable)
    if found:=shutil.which(name):
        candidates.append(Path(found))
    local=TMP_ROOT/"mobile-tools/jdk"
    if local.is_dir():
        candidates.extend(local.rglob("bin/"+executable))
    return next((path.resolve() for path in candidates if path.is_file()),None)


def main() -> int:
    if not JSON_JAR.is_file() or not JSON_SHA.is_file():
        print("Android-compatible JSON test jar is missing",file=sys.stderr)
        return 2
    if hashlib.sha1(JSON_JAR.read_bytes()).hexdigest()!=JSON_SHA.read_text(encoding="ascii").strip():
        print("Android-compatible JSON test jar checksum mismatch",file=sys.stderr)
        return 2
    javac=java_tool("javac")
    java=java_tool("java")
    if not javac or not java:
        print("javac/java not found",file=sys.stderr)
        return 2

    TMP_ROOT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="zcode-capability-header-",dir=TMP_ROOT) as folder:
        work=Path(folder)
        source_root=work/"src"
        classes=work/"classes"
        classes.mkdir()
        sources=[]
        for relative,content in STUBS.items():
            path=source_root/relative
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(content,encoding="utf-8")
            sources.append(path)
        source=ROOT/"mobile/android/src/io/github/try2love/codexbridge"
        sources.extend(source/name for name in (
            "GatewayURL.java","ZCodeConnection.java","GatewayProbe.java","DeviceBinding.java"))
        sources.append(ROOT/"mobile/tests/ZCodeCapabilityHeaderTests.java")
        compile_result=run([
            str(javac),"--release","11","--add-modules","jdk.httpserver","-encoding","UTF-8",
            "-classpath",str(JSON_JAR),"-d",str(classes),*map(str,sources)])
        if compile_result.returncode:
            return compile_result.returncode
        return run([
            str(java),"--add-modules","jdk.httpserver","-ea",
            "-classpath",str(classes)+os.pathsep+str(JSON_JAR),
            "io.github.try2love.codexbridge.ZCodeCapabilityHeaderTests"]).returncode


if __name__=="__main__":
    raise SystemExit(main())
