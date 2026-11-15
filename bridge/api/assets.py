"""Fixed public web URLs, independent of physical feature directories."""
import json
import re
import hashlib
from functools import lru_cache
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlencode, urlsplit

from bridge.resources import project_root
from bridge.web_assets import (
    FONT_ROUTE, PDF_CMAP_ROUTE, PDF_FONT_ROUTE, PUBLIC_FILE_ROUTES,
    STATIC as FIXED_STATIC,
)

# Keep manifest path rewrites local to this API module.
STATIC = dict(FIXED_STATIC)

# The manifest moves files, never expands the public URL allowlist.
_layout = json.loads((project_root() / 'web/assets.json').read_text(encoding='utf-8'))
for _url, (_name, _mime) in list(STATIC.items()):
    _source = _layout.get(_url, _name)
    _sources = tuple(_source) if isinstance(_source, list) else (_source,)
    if not _sources:
        raise ValueError('Empty web asset layout: ' + _url)
    for _relative in _sources:
        _path = PurePosixPath(_relative)
        if _path.is_absolute() or '..' in _path.parts or '\\' in _relative:
            raise ValueError('Invalid web asset layout: ' + _url)
    STATIC[_url] = (_sources if isinstance(_source, list) else _source, _mime)


@lru_cache(maxsize=16)
def _assembled(paths, signatures):
    # Preserve declared CSS cascade order. Cache changes with source metadata,
    # so serving a split stylesheet adds no repeated content reads or HTTP calls.
    return b''.join(Path(path).read_bytes() for path in paths)


def asset_bytes(web_dir, public_path):
    sources, _ = STATIC[public_path]
    if isinstance(sources, str):
        return (Path(web_dir) / sources).read_bytes()
    paths = tuple(str((Path(web_dir) / relative).resolve()) for relative in sources)
    signatures = tuple((stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size) for stat in (Path(path).stat() for path in paths))
    return _assembled(paths, signatures)


VERSION_KEY = 'v'
_HTML_URL = re.compile(rb'(?P<prefix>\b(?:src|href|data-bridge-src|data-bridge-href)\s*=\s*["\'])(?P<url>/[^"\']+)(?P<suffix>["\'])')
_MANIFEST_URL = re.compile(rb'(?P<prefix>"(?:src|href)"\s*:\s*")(?P<url>/[^" ]+)(?P<suffix>")')
_JS_URL = re.compile(rb'(?P<prefix>["\'])(?P<url>/[^"\'\s]+\.(?:js|mjs|css|png|webmanifest)(?:\?[^"\']*)?)(?P<suffix>["\'])')
_CSS_URL = re.compile(rb'url\((?P<quote>["\']?)(?P<url>[^)"\']+)(?P=quote)\)')


def _public_file(web_dir, public_path):
    if public_path in STATIC and public_path != '/':
        return asset_bytes(web_dir, public_path)
    for route, directory in PUBLIC_FILE_ROUTES:
        match = route.fullmatch(public_path)
        if match:
            file = Path(web_dir) / directory / match[1]
            return file.read_bytes() if file.is_file() else None
    return None


def _versioned_url(web_dir, url, parent, seen):
    try:
        value = url.decode('ascii')
    except UnicodeDecodeError:
        return url
    parsed = urlsplit(value)
    path = parsed.path
    if not path.startswith('/'):
        if parent != '/vendor/katex/katex.min.css' or not path.startswith('fonts/'):
            return url
        path = '/vendor/katex/' + path
    if path in seen or path == '/':
        return url
    if _public_file(web_dir, path) is None:
        return url
    digest = hashlib.sha256(served_asset_bytes(web_dir, path, seen)).hexdigest()
    query = [(key, val) for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
             for val in values if key != VERSION_KEY]
    query.append((VERSION_KEY, digest))
    # Keep relative font URLs relative to the stylesheet URL.
    location = parsed.path if not parsed.path.startswith('/') else path
    return (location + '?' + urlencode(query) + (('#' + parsed.fragment) if parsed.fragment else '')).encode('ascii')


def served_asset_bytes(web_dir, public_path, seen=frozenset()):
    """Return the actual public representation, with only known asset references versioned."""
    source = asset_bytes(web_dir, public_path) if public_path in STATIC else _public_file(web_dir, public_path)
    if source is None:
        raise KeyError(public_path)
    if public_path in seen:
        return source
    seen = seen | {public_path}
    if public_path == '/':
        pattern = _HTML_URL
    elif public_path == '/manifest.webmanifest':
        pattern = _MANIFEST_URL
    elif public_path.endswith('.css'):
        pattern = _CSS_URL
    elif public_path.endswith(('.js', '.mjs')) and not public_path.startswith('/vendor/'):
        pattern = _JS_URL
    else:
        return source
    def replace(match):
        updated = _versioned_url(web_dir, match['url'], public_path, seen)
        if pattern is _CSS_URL:
            return b'url(' + match['quote'] + updated + match['quote'] + b')'
        return match['prefix'] + updated + match['suffix']
    return pattern.sub(replace, source)


def current_version(web_dir, public_path):
    return hashlib.sha256(served_asset_bytes(web_dir, public_path)).hexdigest()
