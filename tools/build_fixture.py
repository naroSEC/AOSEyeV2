"""Generate a local DEX/APK analysis fixture using the user's installed JDK and D8.

The APK is an unsigned analysis ZIP with a text manifest, not an installable app.
Android-named compile stubs are excluded from DEX to preserve external references.
"""
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZipFile
from analyzer.app.settings import Settings


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / 'build' / 'fixtures'
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='aoseye-fixture-') as tmp:
        classes = Path(tmp) / 'classes'
        classes.mkdir()
        sources = list((root / 'tests/fixtures/java').rglob('*.java'))
        subprocess.run(['javac', '--release', '8', '-d', str(classes), *map(str, sources)], check=True)
        jar = Path(Settings().jeb_path) / 'bin/app/d8.jar'
        all_classes = list((classes / 'test').glob('*.class'))
        regular = [p for p in all_classes if not p.name.startswith('Boundary')]
        subprocess.run(['java', '-cp', str(jar), 'com.android.tools.r8.D8', '--min-api', '21',
                        '--output', str(output), *map(str, regular)], check=True)
        boundaries = output / 'boundaries'
        boundaries.mkdir(exist_ok=True)
        subprocess.run(['java', '-cp', str(jar), 'com.android.tools.r8.D8', '--min-api', '21',
                        '--output', str(boundaries), *map(str, (p for p in all_classes if p.name.startswith('Boundary')))], check=True)
    with ZipFile(output / 'flow-fixture.apk', 'w') as z:
        z.write(output / 'classes.dex', 'classes.dex')
        z.writestr('AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test"><uses-sdk android:targetSdkVersion="30"/><application android:debuggable="true"><activity android:name=".Main" android:exported="true"/></application></manifest>')
        z.writestr('assets/example.env', 'API_KEY=fixture-only-not-a-real-secret')
    print(output / 'flow-fixture.apk')
    with ZipFile(output / 'boundary-fixture.apk', 'w') as z:
        z.write(boundaries / 'classes.dex', 'classes.dex')
        z.writestr('AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test"><uses-sdk android:targetSdkVersion="30"/><application><activity android:name=".BoundaryEntry" android:exported="true"/><activity android:name=".BoundaryDestination" android:exported="false"/></application></manifest>')
    print(output / 'boundary-fixture.apk')


if __name__ == '__main__':
    main()
