#!/usr/bin/env python3
"""Compile the real Android ZCode account flow and run JVM-only provider tests."""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY_PATH = ROOT / "scripts/test-zcode-capability-headers.py"

spec = importlib.util.spec_from_file_location("zcode_capability_headers_fixture", CAPABILITY_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load ZCode capability header fixture")
CAPABILITY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CAPABILITY)

URI_STUB = """package android.net;
public final class Uri {
 public static String encode(String value,String allow){
  if(value==null)return null;
  StringBuilder encoded=new StringBuilder();
  for(byte raw:value.getBytes(java.nio.charset.StandardCharsets.UTF_8)){
   int c=raw&0xff;
   if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||"-_.~".indexOf(c)>=0||allow.indexOf(c)>=0)
    encoded.append((char)c);
   else encoded.append('%').append(Character.toUpperCase(Character.forDigit(c>>>4,16)))
    .append(Character.toUpperCase(Character.forDigit(c&15,16)));
  }
  return encoded.toString();
 }
}
"""

# Reuse only the Android platform stubs needed by the real ZCodeAccount. Importing the
# capability fixture above lets both JVM regressions keep one definition of these stubs;
# its ZCodeAccount stub is deliberately excluded from ACCOUNT_STUB_NAMES.
ACCOUNT_STUB_NAMES = (
    "android/content/Context.java",
    "android/content/MemoryPrefs.java",
    "android/content/SharedPreferences.java",
    "android/security/keystore/KeyGenParameterSpec.java",
    "android/security/keystore/KeyProperties.java",
    "android/util/Base64.java",
)
STUBS = {name: CAPABILITY.STUBS[name] for name in ACCOUNT_STUB_NAMES}
STUBS["android/net/Uri.java"] = URI_STUB


def main() -> int:
    json_jar = CAPABILITY.JSON_JAR
    json_sha = CAPABILITY.JSON_SHA
    if not json_jar.is_file() or not json_sha.is_file():
        print("Android-compatible JSON test jar is missing", file=sys.stderr)
        return 2
    expected_sha = json_sha.read_text(encoding="ascii").strip().lower()
    actual_sha = hashlib.sha1(json_jar.read_bytes()).hexdigest().lower()
    if actual_sha != expected_sha:
        print("Android-compatible JSON test jar checksum mismatch", file=sys.stderr)
        return 2

    javac = CAPABILITY.java_tool("javac")
    java = CAPABILITY.java_tool("java")
    if not javac or not java:
        print("javac/java not found", file=sys.stderr)
        return 2

    CAPABILITY.TMP_ROOT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="zcode-account-provider-", dir=CAPABILITY.TMP_ROOT) as folder:
        work = Path(folder)
        source_root = work / "src"
        classes = work / "classes"
        classes.mkdir()
        sources = []
        for relative in (*ACCOUNT_STUB_NAMES, "android/net/Uri.java"):
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(STUBS[relative], encoding="utf-8")
            sources.append(path)
        sources.append(ROOT / "mobile/android/src/io/github/try2love/codexbridge/ZCodeAccount.java")
        sources.append(ROOT / "mobile/tests/ZCodeAccountProviderTests.java")

        compile_result = CAPABILITY.run([
            str(javac), "--release", "11", "-encoding", "UTF-8",
            "-classpath", str(json_jar), "-d", str(classes), *map(str, sources)
        ])
        if compile_result.returncode:
            return compile_result.returncode
        return CAPABILITY.run([
            str(java), "-ea", "-classpath", str(classes) + os.pathsep + str(json_jar),
            "io.github.try2love.codexbridge.ZCodeAccountProviderTests"
        ]).returncode


if __name__ == "__main__":
    raise SystemExit(main())
