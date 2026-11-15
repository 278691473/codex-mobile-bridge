#!/usr/bin/env python3
"""Compile the real ZCodeConnection helper against isolated .tmp stubs and run concurrency checks."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = ROOT / ".tmp"

STUBS = {
    "android/content/Context.java": """package android.content;
import java.util.concurrent.ConcurrentHashMap;
public class Context {
 private static final ConcurrentHashMap<String,SharedPreferences> PREFS=new ConcurrentHashMap<>();
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
 public Editor edit(){return new Editor(){public Editor putString(String key,String value){values.put(key,value);return this;}public Editor putInt(String key,int value){values.put(key,value);return this;}public Editor clear(){values.clear();return this;}public boolean commit(){return true;}};}
}
""",
    "io/github/try2love/codexbridge/ZCodePairing.java": """package io.github.try2love.codexbridge;
final class ZCodePairing {
 final String sid,mid,name;
 ZCodePairing(String sid,String mid,String name){this.sid=sid;this.mid=mid;this.name=name;}
}
""",
    "io/github/try2love/codexbridge/ZCodeAccount.java": """package io.github.try2love.codexbridge;
import android.content.Context;
import java.util.concurrent.atomic.AtomicInteger;
final class ZCodeAccount {
 static volatile String jwt="";
 static final AtomicInteger saveCalls=new AtomicInteger();
 static void reset(String value){jwt=value;saveCalls.set(0);}
 static String load(Context context){return jwt;}
 static void verifyDevice(String value,String sid,String mid)throws Exception{if(value==null||value.isEmpty())throw new Exception("missing jwt");}
 static void save(Context context,String value){jwt=value;saveCalls.incrementAndGet();}
 static void clear(Context context){jwt="";}
}
""",
    "io/github/try2love/codexbridge/ZCodeTransport.java": """package io.github.try2love.codexbridge;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
final class ZCodeTransport {
 static volatile boolean blockConnect;
 static volatile CountDownLatch connectEntered;
 static volatile CountDownLatch connectRelease;
 static volatile CountDownLatch closeEntered;
 static volatile CountDownLatch closeRelease;
 static final AtomicBoolean blockNextClose=new AtomicBoolean();
 static final AtomicInteger closeCalls=new AtomicInteger();
 private volatile boolean connected;
 static void reset(){blockConnect=false;connectEntered=new CountDownLatch(1);connectRelease=new CountDownLatch(1);closeEntered=new CountDownLatch(1);closeRelease=new CountDownLatch(1);blockNextClose.set(false);closeCalls.set(0);}
 ZCodeTransport(String jwt,String sid,String mid){}
 void connect()throws Exception{if(blockConnect){connectEntered.countDown();if(!connectRelease.await(5,TimeUnit.SECONDS))throw new Exception("connect latch timeout");}connected=true;}
 boolean isConnected(){return connected;}
 boolean isKicked(){return false;}
 void close(){closeCalls.incrementAndGet();if(blockNextClose.compareAndSet(true,false)){closeEntered.countDown();try{closeRelease.await(5,TimeUnit.SECONDS);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}}
}
""",
    "io/github/try2love/codexbridge/ZCodeLocalGateway.java": """package io.github.try2love.codexbridge;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
final class ZCodeLocalGateway {
 static final AtomicInteger created=new AtomicInteger();
 static final AtomicInteger closed=new AtomicInteger();
 private final ZCodeTransport transport;
 private final int port;
 private final int id;
 private final AtomicBoolean done=new AtomicBoolean();
 static void reset(){created.set(0);closed.set(0);}
 ZCodeLocalGateway(ZCodeTransport transport,int port){this.transport=transport;this.port=port;this.id=created.incrementAndGet();}
 String start()throws Exception{return "http://127.0.0.1:"+port;}
 String capabilityCookie(){return "zcode_cap=cap-"+id;}
 void close(){if(done.compareAndSet(false,true))closed.incrementAndGet();}
}
""",
}


def run(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result


def java_tool(name: str) -> Path | None:
    executable_name = name + (".exe" if sys.platform == "win32" else "")
    candidates = []
    for variable in ("JAVA_HOME", "JDK_HOME"):
        if value := os.environ.get(variable):
            candidates.append(Path(value) / "bin" / executable_name)
    if found := shutil.which(name):
        candidates.append(Path(found))
    local_jdk = TMP_ROOT / "mobile-tools" / "jdk"
    if local_jdk.is_dir():
        candidates.extend(local_jdk.rglob("bin/" + executable_name))
    return next((path.resolve() for path in candidates if path.is_file()), None)


def main() -> int:
    javac = java_tool("javac")
    java = java_tool("java")
    if not javac or not java:
        print("javac/java not found", file=sys.stderr)
        return 2

    activity = (
        ROOT
        / "mobile/android/src/io/github/try2love/codexbridge/MainActivity.java"
    ).read_text(encoding="utf-8")
    production_order = (
        "if(attempt!=relayLoginGeneration)return;"
        "ZCodeConnection.save(getApplicationContext(),target);"
        "ZCodeAccount.save(getApplicationContext(),jwt);"
        "ZCodeConnection.close();"
    )
    if production_order not in activity:
        print(
            "MainActivity pairing order changed: target save must precede JWT save and close",
            file=sys.stderr,
        )
        return 1

    TMP_ROOT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="zcode-connection-concurrency-", dir=TMP_ROOT
    ) as folder:
        work = Path(folder)
        source_root = work / "src"
        classes = work / "classes"
        classes.mkdir()
        helper_sources: list[Path] = []

        for relative, content in STUBS.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            helper_sources.append(path)

        helper_sources.append(
            ROOT
            / "mobile/android/src/io/github/try2love/codexbridge/ZCodeConnection.java"
        )
        helper_result = run([
            str(javac),
            "--release",
            "11",
            "-encoding",
            "UTF-8",
            "-d",
            str(classes),
            *map(str, helper_sources),
        ])
        if helper_result.returncode:
            return helper_result.returncode
        helper_class = classes / "io/github/try2love/codexbridge/ZCodeConnection.class"
        if not helper_class.is_file():
            print("compiled helper class missing: " + str(helper_class), file=sys.stderr)
            return 1

        test_source = ROOT / "mobile/tests/ZCodeConnectionConcurrencyTests.java"
        test_compile = run([
            str(javac),
            "--release",
            "11",
            "-encoding",
            "UTF-8",
            "-classpath",
            str(classes),
            "-d",
            str(classes),
            str(test_source),
        ])
        if test_compile.returncode:
            return test_compile.returncode

        test_result = run([
            str(java),
            "-ea",
            "-cp",
            str(classes),
            "io.github.try2love.codexbridge.ZCodeConnectionConcurrencyTests",
        ])
        return test_result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
