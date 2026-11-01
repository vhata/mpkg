#!/usr/bin/env python3
"""Acquire only the fixture's pinned Python/AUR sources and recipes."""
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request

import runner
import native

ALLOWED_HOSTS = {'www.python.org','cpan.metacpan.org','raw.githubusercontent.com',
                 'github.com','codeload.github.com'}


def source_url(url):
    parsed=urllib.parse.urlsplit(url)
    if (parsed.scheme!='https' or parsed.netloc not in ALLOWED_HOSTS
            or parsed.query or parsed.fragment or '\\' in parsed.path
            or '..' in Path(parsed.path).parts):
        raise ValueError('source URL is outside the pinned HTTPS source hosts')
    return url


class SourceRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        source_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def records():
    manifest=json.loads(native.MANIFEST.read_text());python=manifest['python_runtime']
    result=[{'kind':'python','package':'python','name':'Python-3.12.16.tar.xz',
             'url':python['source_url'],'digests':{'sha256':python['sha256_published']}}]
    for package in manifest['aur_packages']:
        for name,recipe in package['recipe_files'].items():
            result.append({'kind':'recipe','package':package['package_base'],'name':name,
                           'url':recipe['url'],'digests':{'sha256':recipe['sha256_computed']}})
        for source in package['sources']:
            digests=dict(source['digests_published_in_recipe'])
            if 'sha256_published_in_upstream_build_info' in source:
                digests['sha256']=source['sha256_published_in_upstream_build_info']
            result.append({'kind':'aur-source','package':package['package_base'],
                           'name':source['filename'],'url':source['url'],'digests':digests})
    return result


def validate_record(record):
    source_url(record['url'])
    if Path(record['name']).name!=record['name'] or record['name'] in {'.','..'}:
        raise ValueError('unsafe source filename')
    if not record['digests'] or set(record['digests'])-{'sha256','sha512'}:
        raise ValueError('unsupported source digest')
    for algorithm,digest in record['digests'].items():
        if len(digest)!=hashlib.new(algorithm).digest_size*2 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('invalid pinned source digest')


def verify(path,record):
    runner.regular_file(path)
    if path.stat().st_size>128*1024**2:raise ValueError('source exceeds 128 MiB bound')
    for algorithm,expected in record['digests'].items():
        with path.open('rb') as stream:observed=hashlib.file_digest(stream,algorithm).hexdigest()
        if observed!=expected:raise ValueError(f"source digest mismatch: {record['package']}/{record['name']}")


def acquire():
    destination=runner.private_directory(runner.CACHE/'sources')
    results=[]
    for record in records():
        validate_record(record)
        key=next(iter(record['digests'].values()))
        path=destination/(key+'.source')
        if not path.exists():
            partial=path.with_name(path.name+'.part')
            fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),SourceRedirect())
                count=0
                with os.fdopen(fd,'wb') as output,runner.artifact_deadline(),opener.open(record['url'],timeout=60) as response:
                    if response.status!=200:raise ValueError('source server did not return HTTP 200')
                    while chunk:=response.read(1024**2):
                        count+=len(chunk)
                        if count>128*1024**2:raise ValueError('source exceeds 128 MiB bound')
                        output.write(chunk)
                    output.flush();os.fsync(output.fileno())
                verify(partial,record)
                os.link(partial,path,follow_symlinks=False)
            finally:partial.unlink(missing_ok=True)
        verify(path,record)
        results.append({**record,'cache_file':path.name,'bytes':path.stat().st_size,
                        'computed_sha256':runner.sha256(path),
                        'authentication':'pinned digests from official Python release or accepted AUR recipe; HTTPS',
                        'source_signature_verified':False})
        print(f"verified source {record['package']}/{record['name']}",flush=True)
    runner.write_new(runner.CACHE/'source-acquisition.json',(json.dumps(results,indent=2)+'\n').encode())


if __name__=='__main__':
    if sys.version_info[:2]!=(3,12):raise SystemExit('Python 3.12 is required')
    if len(sys.argv)!=1:raise SystemExit('This command accepts no arguments.')
    os.umask(0o077)
    acquire()
