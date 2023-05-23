#!/usr/bin/env python3

import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


def natsort_key(text, regex=re.compile(r'(\d+)')):
    return [int(s) if s.isdigit() else s for s in regex.split(text)]


def newest_child_by_name(directory):
    children = os.listdir(directory)
    if not children:
        raise ValueError(f'{directory} has no children')

    child = sorted(children, key=natsort_key)[-1]
    return os.path.join(directory, child)


def build_empty_zip():
    stream = io.BytesIO()

    with zipfile.ZipFile(stream, 'w'):
        pass

    return stream.getvalue()


def build_dex(sources):
    if 'ANDROID_HOME' not in os.environ:
        raise ValueError('ANDROID_HOME must be set to the Android SDK path')

    sdk = os.environ['ANDROID_HOME']
    build_tools = newest_child_by_name(os.path.join(sdk, 'build-tools'))
    platform = newest_child_by_name(os.path.join(sdk, 'platforms'))
    d8 = os.path.join(build_tools, 'd8')
    android_jar = os.path.join(platform, 'android.jar')

    with tempfile.TemporaryDirectory() as temp_dir:
        subprocess.check_call([
            'javac',
            '-source', '1.8',
            '-target', '1.8',
            '-cp', android_jar,
            '-d', temp_dir,
            *sources,
        ])

        class_files = []
        for root, _, files in os.walk(temp_dir):
            for f in files:
                if f.endswith('.class'):
                    class_files.append(os.path.join(root, f))

        subprocess.check_call([
            d8,
            '--output', temp_dir,
            *class_files,
        ])

        with open(os.path.join(temp_dir, 'classes.dex'), 'rb') as f:
            return f.read()


def parse_props(raw_prop):
    result = {}

    for line in raw_prop.decode('UTF-8').splitlines():
        k, delim, v = line.partition('=')
        if not delim:
            raise ValueError(f'Malformed line: {repr(line)}')

        result[k.strip()] = v.strip()

    return result


def build_module(dist_dir, common_dir, module_dir, extra_files):
    with open(os.path.join(module_dir, 'module.prop'), 'rb') as f:
        module_prop_raw = f.read()
        module_prop = parse_props(module_prop_raw)

    name = module_prop['name']
    version = module_prop['version'].removeprefix('v')
    zip_path = os.path.join(dist_dir, f'{name}-{version}.zip')

    with zipfile.ZipFile(zip_path, 'w') as z:
        file_map = {
            'META-INF/com/google/android/update-binary': {
                'file': os.path.join(common_dir, 'update-binary'),
            },
            'META-INF/com/google/android/updater-script': {
                'file': os.path.join(common_dir, 'updater-script'),
            },
            'module.prop': {
                'data': module_prop_raw,
            },
            **extra_files,
        }

        for name, source in sorted(file_map.items()):
            # Build our own ZipInfo to ensure archive is reproducible
            info = zipfile.ZipInfo(name)
            with z.open(info, 'w') as f_out:
                if 'data' in source:
                    f_out.write(source['data'])
                else:
                    with open(source['file'], 'rb') as f_in:
                        shutil.copyfileobj(f_in, f_out)

    return zip_path


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('module', nargs='*',
                        default=('clearotacerts', 'oemunlockonboot'),
                        help='Module to build')

    return parser.parse_args()


def main():
    args = parse_args()

    dist_dir = os.path.join(sys.path[0], 'dist')
    os.makedirs(dist_dir, exist_ok=True)

    common_dir = os.path.join(sys.path[0], 'common')

    for module in args.module:
        module_dir = os.path.join(sys.path[0], module)

        if module == 'clearotacerts':
            extra_files = {
                'system/etc/security/otacerts.zip': {
                    'data': build_empty_zip(),
                },
            }
        elif module == 'oemunlockonboot':
            extra_files = {
                'classes.dex': {
                    'data': build_dex([os.path.join(module_dir, 'Main.java')]),
                },
                'service.sh': {
                    'file': os.path.join(module_dir, 'service.sh'),
                },
            }
        else:
            raise ValueError(f'Invalid module: {module}')

        module_zip = build_module(dist_dir, common_dir, module_dir, extra_files)
        print('Built module', module_zip)


if __name__ == '__main__':
    main()
