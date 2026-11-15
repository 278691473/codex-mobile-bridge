#!/usr/bin/env python3
"""Compile the production Android relay and exercise loopback errors and recovery."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('zcode_capability_fixture',ROOT/'scripts/test-zcode-capability-headers.py')
fixture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
tools=ROOT/'.tmp/mobile-tools'
jars=[tools/name for name in ('android-json-0.0.20131108.vaadin1.jar','Java-WebSocket-1.5.7.jar','slf4j-api-2.0.16.jar','slf4j-nop-2.0.16.jar')]
for jar in jars:
 checksum=jar.with_suffix('.jar.sha1')
 if not jar.is_file() or not checksum.is_file() or hashlib.sha1(jar.read_bytes()).hexdigest()!=checksum.read_text(encoding='ascii').strip():
  raise SystemExit('Provide the relay test JAR and its published SHA-1: '+jar.name)
classpath=os.pathsep.join(map(str,jars))
javac,java=fixture.java_tool('javac'),fixture.java_tool('java')
if not javac or not java:
 raise SystemExit('javac/java not found')
with tempfile.TemporaryDirectory(prefix='zcode-transport-',dir=ROOT/'.tmp') as folder:
 work=Path(folder)
 source=ROOT/'mobile/android/src/io/github/try2love/codexbridge'
 tests=ROOT/'mobile/tests'
 subprocess.run([str(javac),'--release','8','-encoding','UTF-8','-cp',classpath,'-d',str(work),
  str(source/'ZCodeTransport.java'),str(source/'ZCodeLocalGateway.java'),
  str(tests/'ZCodeTransportTests.java'),str(tests/'ZCodeTransportRecoveryTests.java')],check=True)
 for name in ('ZCodeTransportTests','ZCodeTransportRecoveryTests'):
  subprocess.run([str(java),'-ea','-cp',str(work)+os.pathsep+classpath,'io.github.try2love.codexbridge.'+name],check=True,timeout=45)
