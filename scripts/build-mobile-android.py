#!/usr/bin/env python3
"""Build a local debug APK using project-local JDK/SDK; never installs tools."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path, default=ROOT/'dist/mobile-preview')
options = parser.parse_args()
tools = ROOT/'.tmp/mobile-tools'


def executable(directory, name):
    if os.name == 'nt':
        candidates = (directory/f'{name}.exe', directory/f'{name}.bat', directory/name)
    else:
        candidates = (directory/name,)
    return next((path for path in candidates if path.is_file()), candidates[0])


def find_jdk():
    candidates = []
    local_jdk = tools/'jdk'
    if local_jdk.is_dir():
        candidates.append(local_jdk)
        for child in local_jdk.iterdir():
            candidates.extend((child, child/'Contents'/'Home'))
    for variable in ('JAVA_HOME', 'JDK_HOME'):
        if os.environ.get(variable):
            candidates.append(Path(os.environ[variable]))
    javac = shutil.which('javac')
    if javac:
        candidates.append(Path(javac).resolve().parents[1])
    seen = set()
    for candidate in candidates:
        candidate = candidate.expanduser().resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        if executable(candidate/'bin', 'javac').is_file():
            return candidate
    raise SystemExit('Place a JDK 17 in .tmp/mobile-tools/jdk or set JAVA_HOME.')


def find_sdk():
    candidates = [tools/'sdk']
    for variable in ('ANDROID_SDK_ROOT', 'ANDROID_HOME'):
        if os.environ.get(variable):
            candidates.append(Path(os.environ[variable]))
    for sdk in candidates:
        if not sdk.is_dir():
            continue
        for build_tools in (sdk/'build-tools').glob('*'):
            if all(executable(build_tools, name).is_file() for name in ('aapt2', 'd8', 'zipalign', 'apksigner')):
                android = next((path for path in sorted((sdk/'platforms').glob('*/android.jar'), reverse=True) if path.is_file()), None)
                if android is not None:
                    return sdk, build_tools, android
    raise SystemExit('Place Android Build-Tools/Platform 35 in .tmp/mobile-tools/sdk or set ANDROID_SDK_ROOT.')


jdk = find_jdk()
sdk, build_tools, android = find_sdk()
artifacts = {
    'ZXing': tools/'zxing-core-3.5.3.jar',
    'Java-WebSocket': tools/'Java-WebSocket-1.5.7.jar',
    'SLF4J API': tools/'slf4j-api-2.0.16.jar',
    'SLF4J NOP': tools/'slf4j-nop-2.0.16.jar',
}
for name, path in artifacts.items():
    checksum = path.with_name('zxing.sha1' if name == 'ZXing' else path.name + '.sha1')
    if not path.is_file() or not checksum.is_file():
        raise SystemExit(f'Missing {name} artifact or published SHA-1: {path}')
    expected = checksum.read_text().strip().split()[0].lower()
    actual = hashlib.sha1(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f'{name} checksum mismatch')

work = tools/'android-build'
work.mkdir(parents=True, exist_ok=True)
for name in ('gen', 'classes', 'dex'):
    folder = work/name
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir()
env = {
    **os.environ,
    'JAVA_HOME': str(jdk),
    'ANDROID_SDK_ROOT': str(sdk),
    'PATH': str(jdk/'bin') + os.pathsep + os.environ.get('PATH', ''),
}


def run(*args):
    values = []
    for arg in args:
        if isinstance(arg, Path):
            try:
                arg = arg.resolve().relative_to(ROOT)
            except ValueError:
                pass
        values.append(str(arg))
    subprocess.run(values, env=env, check=True, cwd=ROOT)


source = ROOT/'mobile/android'
run(executable(build_tools, 'aapt2'), 'compile', '--dir', source/'res', '-o', work/'resources.zip')
run(executable(build_tools, 'aapt2'), 'link', '-I', android, '--manifest', source/'AndroidManifest.xml', '--java', work/'gen', '-o', work/'base.apk', work/'resources.zip')
jars = tuple(artifacts.values())
java = list((source/'src').rglob('*.java')) + list((work/'gen').rglob('*.java'))
run(executable(jdk/'bin', 'javac'), '-encoding', 'UTF-8', '--release', '8', '-classpath', os.pathsep.join(map(str, (android, *jars))), '-d', work/'classes', *java)
run(executable(build_tools, 'd8'), '--lib', android, '--min-api', '26', '--output', work/'dex', *list((work/'classes').rglob('*.class')), *jars)
shutil.copy2(work/'base.apk', work/'unsigned.apk')
with zipfile.ZipFile(work/'unsigned.apk', 'a') as archive:
    for path in (work/'dex').glob('*.dex'):
        archive.write(path,path.name)
    for directory in (ROOT/'mobile/shared/web', source/'assets', ROOT/'web/client-icons'):
        for asset in directory.glob('*.js'):
            archive.write(asset,'assets/'+asset.name)
    for provider in ('codex', 'claude', 'deepseek'):
        archive.write(ROOT/'web/client-icons'/f'{provider}.png', 'assets/'+provider+'.png')
    archive.write(ROOT/'mobile/NOTICE.md','assets/NOTICE.md')
    with zipfile.ZipFile(artifacts['SLF4J NOP']) as nop:
        archive.writestr('META-INF/services/org.slf4j.spi.SLF4JServiceProvider', nop.read('META-INF/services/org.slf4j.spi.SLF4JServiceProvider'))
    archive.write(ROOT/'mobile/licenses/ZXing-LICENSE.txt','assets/ZXing-LICENSE.txt')
    archive.write(ROOT/'mobile/licenses/Java-WebSocket-LICENSE.txt','assets/Java-WebSocket-LICENSE.txt')
    archive.write(ROOT/'mobile/licenses/SLF4J-LICENSE.txt','assets/SLF4J-LICENSE.txt')
key = tools/'preview-debug.p12'
if not key.exists():
    run(executable(jdk/'bin', 'keytool'), '-genkeypair', '-keystore', key, '-storepass', 'android', '-keypass', 'android', '-alias', 'preview', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '3650', '-dname', 'CN=Bridge Local Preview')
run(executable(build_tools, 'zipalign'), '-f', '4', work/'unsigned.apk', work/'aligned.apk')
out = options.output_dir.resolve()
out.mkdir(parents=True,exist_ok=True)
version = json.loads((ROOT/'package.json').read_text(encoding='utf-8'))['version']
apk = out/('Codex-Mobile-Bridge-'+version+'-Android.apk')
run(executable(build_tools, 'apksigner'), 'sign', '--ks', key, '--ks-pass', 'pass:android', '--out', apk, work/'aligned.apk')
run(executable(build_tools, 'apksigner'), 'verify', '--verbose', apk)
print(apk)
print('SHA-256',hashlib.sha256(apk.read_bytes()).hexdigest())
