import os

from strictyaml import load, Int, Map, MapPattern, Regex, Seq, Str


CONFIG_PATH = os.path.join(
    os.path.realpath(os.path.dirname(__file__)), 'tests.yaml')

SHA256_HEX = Regex('[0-9a-fA-F]{64}')

SCHEMA = Map({
    'magisk': Map({
        'url': Str(),
        'hash': SHA256_HEX,
    }),
    'device': MapPattern(Str(), Map({
        'url': Str(),
        'sections': Seq(Map({
            'start': Int(),
            'end': Int(),
        })),
        'hash': Map({
            'original': Map({
                'full': SHA256_HEX,
                'stripped': SHA256_HEX,
            }),
            'patched': Map({
                'full': SHA256_HEX,
                'stripped': SHA256_HEX,
            }),
            'avb_images': MapPattern(Str(), SHA256_HEX),
        }),
    })),
})


def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return load(f.read(), SCHEMA)


def save_config(data):
    with open(CONFIG_PATH, 'w') as f:
        f.write(data.as_yaml())
