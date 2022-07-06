import io
import os
import shutil
import sys
import zipfile


def build_empty_zip():
    stream = io.BytesIO()

    with zipfile.ZipFile(stream, 'w') as z:
        pass

    return stream.getvalue()


def parse_props(raw_prop):
    result = {}

    for line in raw_prop.decode('UTF-8').splitlines():
        k, delim, v = line.partition('=')
        if not delim:
            raise ArgumentError(f'Malformed line: {repr(line)}')

        result[k.strip()] = v.strip()

    return result


def main():
    dist_dir = os.path.join(sys.path[0], 'dist')
    os.makedirs(dist_dir, exist_ok=True)

    module_prop_path = os.path.join(sys.path[0], 'module.prop')

    with open(os.path.join(sys.path[0], 'module.prop'), 'rb') as f:
        module_prop_raw = f.read()
        module_prop = parse_props(module_prop_raw)

    name = module_prop['name']
    version = module_prop['version'].removeprefix('v')
    zip_path = os.path.join(dist_dir, f'{name}-{version}.zip')

    with zipfile.ZipFile(zip_path, 'w') as z:
        for name, data in (
            ('META-INF/com/google/android/update-binary', None),
            ('META-INF/com/google/android/updater-script', None),
            ('module.prop', module_prop_raw),
            ('system/etc/security/otacerts.zip', build_empty_zip()),
        ):
            # Build our own ZipInfo to ensure archive is reproducible
            info = zipfile.ZipInfo(name)
            with z.open(info, 'w') as f_out:
                if data is not None:
                    f_out.write(data)
                else:
                    with open(os.path.join(sys.path[0], name), 'rb') as f_in:
                        shutil.copyfileobj(f_in, f_out)


if __name__ == '__main__':
    main()
