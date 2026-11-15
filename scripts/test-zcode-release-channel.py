#!/usr/bin/env python3
"""Run fork update-channel rejection against Android-compatible JSON and real HTTP."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
jar = root/'.tmp/mobile-tools/android-json-0.0.20131108.vaadin1.jar'
checksum = jar.with_suffix('.jar.sha1')
if not jar.is_file() or not checksum.is_file() or hashlib.sha1(jar.read_bytes()).hexdigest() != checksum.read_text().strip():
    raise SystemExit('Provide the Android-compatible JSON test jar and its published SHA-1 in .tmp/mobile-tools.')
work = root/'.tmp/fork-channel-tests'
work.mkdir(parents=True, exist_ok=True)
jdk = Path(os.environ['JAVA_HOME'])/'bin' if os.environ.get('JAVA_HOME') else None
def tool(name):
    return str(jdk/(name + ('.exe' if os.name == 'nt' else ''))) if jdk else shutil.which(name)
source = root/'mobile/android/src/io/github/try2love/codexbridge'
subprocess.run([tool('javac'), '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(work),
                *[str(source/(name+'.java')) for name in ('GatewayURL', 'MobileRelease', 'ArtifactDownload', 'GatewayUpdate')],
                str(root/'mobile/tests/GatewayUpdateChannelTests.java')], check=True)
subprocess.run([tool('java'), '-cp', str(work)+os.pathsep+str(jar),
                'io.github.try2love.codexbridge.GatewayUpdateChannelTests'], check=True)
