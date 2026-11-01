"""Host boundary tests for disposable-fixture acquisition and extraction."""
import importlib.util
import ast
import copy
import hashlib
import re
import base64
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import os
import subprocess
import sys
from unittest import mock
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location(
    'fixture_runner', Path(__file__).resolve().parents[1] / 'scripts/fixture/runner.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class FixtureExtractionTests(unittest.TestCase):
    def archive(self, entries):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as tar:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    value = value.encode() if isinstance(value, str) else value
                    member.size = len(value)
                    member.mode = 0o6755
                    tar.addfile(member, io.BytesIO(value))
                else:
                    member.linkname = value
                    tar.addfile(member)
        output.seek(0)
        return output

    def test_escape_and_special_members_are_rejected_before_writes(self):
        cases = [('..','0',''), ('/outside','0',''), ('usr/link','2','../../outside'),
                 ('usr/link','2','/../outside'), ('usr/link','1','../outside'), ('dev/a','3','')]
        for name, kind, target in cases:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as tmp:
                archive = self.archive([('safe', tarfile.REGTYPE, b'unchanged'),
                                        (name, kind.encode(), target)])
                with self.assertRaises(ValueError):
                    RUNNER.extract_tar(archive, Path(tmp)/'root')
                self.assertFalse((Path(tmp)/'root/safe').exists())

    def test_existing_parent_symlink_is_never_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';root.mkdir();outside=Path(tmp)/'outside';outside.mkdir()
            (root/'usr').symlink_to(outside, target_is_directory=True)
            archive=self.archive([('usr/escape',tarfile.REGTYPE,b'bad')])
            with self.assertRaises(ValueError):RUNNER.extract_tar(archive,root)
            self.assertFalse((outside/'escape').exists())

    def test_internal_links_and_regular_files_strip_privileged_bits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root'
            archive=self.archive([('usr/bin/tool',tarfile.REGTYPE,b'ok'),
                                  ('usr/bin/alias',tarfile.SYMTYPE,'tool')])
            RUNNER.extract_tar(archive,root)
            self.assertEqual((root/'usr/bin/tool').read_bytes(),b'ok')
            self.assertEqual((root/'usr/bin/tool').stat().st_mode & 0o7777,0o755)
            self.assertEqual((root/'usr/bin/alias').read_bytes(),b'ok')

    def test_package_absolute_symlink_is_rebased_inside_private_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root'
            archive=self.archive([('usr/share/doc/xz/COPYING',tarfile.REGTYPE,b'license'),
                                  ('usr/share/licenses/xz/COPYING',tarfile.SYMTYPE,'/usr/share/doc/xz/COPYING')])
            RUNNER.extract_tar(archive,root)
            link=root/'usr/share/licenses/xz/COPYING'
            self.assertFalse(Path(link.readlink()).is_absolute())
            self.assertEqual(link.read_bytes(),b'license')
            self.assertTrue(link.resolve().is_relative_to(root))

    def test_cache_paths_and_writes_reject_existing_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'alias').symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):RUNNER.private_directory(root/'alias/child')
            (root/'target').symlink_to(root/'absent')
            with self.assertRaises(FileExistsError):RUNNER.write_new(root/'target',b'bad')

    def test_acquisition_rejects_other_hosts_credentials_and_traversal(self):
        for url in ['http://archive.archlinux.org/a','https://evil.invalid/a',
                    'https://user@archive.archlinux.org/a','https://archive.archlinux.org/../a',
                    'https://archive.archlinux.org/a?token=secret']:
            with self.subTest(url=url),self.assertRaises(ValueError):RUNNER.checked_url(url)


class FixtureTrustTests(unittest.TestCase):
    def test_failed_initialization_never_publishes_a_partial_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cache=root/'fixture';cache.mkdir();keys=root/'keys';keys.mkdir()
            for name in ('archlinux.gpg','archlinux-revoked'):(keys/name).write_text('')
            (keys/'archlinux-trusted').write_text('A'*40+':4:\n')
            result=SimpleNamespace(returncode=2,stderr=b'explicit failure')
            with mock.patch.object(RUNNER,'KEYRINGS',keys), mock.patch.object(RUNNER,'run_gpg',return_value=result):
                with self.assertRaises(RuntimeError):RUNNER.trust_home(cache)
            self.assertFalse((root/'g').exists())
            diagnostics=list(root.glob('gpg-failed-*/failed-step-0.txt'))
            self.assertEqual(len(diagnostics),1)
            self.assertEqual(diagnostics[0].read_bytes(),b'explicit failure')

    def test_good_signature_without_full_trust_and_revoked_primary_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);artifact=root/'artifact';artifact.write_bytes(b'archive')
            signature=root/'signature';signature.write_bytes(b'signature')
            primary='A'*40;signer='B'*40
            (root/'archlinux-revoked').write_text('')
            valid=f'[GNUPG:] VALIDSIG {signer} 2026-11-01 123 0 4 0 1 10 00 {primary}\n'
            for trust,revoked in [('TRUST_UNDEFINED',''),('TRUST_FULLY',primary)]:
                (root/'archlinux-revoked').write_text(revoked+'\n')
                result=SimpleNamespace(returncode=0,stdout=(valid+f'[GNUPG:] {trust} 0 pgp\n').encode())
                with mock.patch.object(RUNNER,'KEYRINGS',root),mock.patch.object(RUNNER,'run_gpg',return_value=result):
                    with self.assertRaises(ValueError):RUNNER.verify_signature(root,artifact,signature)


class FixtureGuestBoundaryTests(unittest.TestCase):
    def test_bootstrap_rejects_unbound_host_before_any_mutation(self):
        script=Path(__file__).resolve().parents[1]/'scripts/fixture/guest-bootstrap.sh'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);bin_dir=root/'bin';bin_dir.mkdir();marker=root/'mutation'
            for name in ('mount','sfdisk','mkfs.fat','mkfs.ext4','pacstrap','pacman-key','arch-chroot'):
                stub=bin_dir/name
                stub.write_text('#!/bin/sh\nprintf forbidden > "$MPKG_TEST_MUTATION"\nexit 99\n')
                stub.chmod(0o755)
            env={'PATH':str(bin_dir)+':/usr/bin:/bin','MPKG_TEST_MUTATION':str(marker),
                 'MPKG_GUEST_ID':'00000000-0000-4000-8000-000000000000'}
            result=subprocess.run(['/usr/bin/bash',str(script)],env=env,capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(marker.exists())

    def test_qemu_options_expose_only_bound_virtual_disks_and_private_channels(self):
        sys.modules.setdefault('runner',RUNNER)
        spec=importlib.util.spec_from_file_location('fixture_vm',Path(__file__).resolve().parents[1]/'scripts/fixture/vm.py')
        vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
        identity={'guest_id':'00000000-0000-4000-8000-000000000000','disk_serial':'mpkg0000000000004000'}
        args=vm.qemu_arguments(identity,True,True)
        joined=' '.join(args)
        for forbidden in ('hostfwd','-virtfs','-fsdev','/dev/kvm','docker.sock','-daemonize'):
            self.assertNotIn(forbidden,joined)
        self.assertIn('dump-guest-core=off',joined)
        self.assertIn('readonly=on,file=/run/mpkg-fixture/inputs.img',joined)
        self.assertEqual(args[args.index('-uuid')+1],identity['guest_id'])
        transferred=' '.join(vm.qemu_arguments(identity,False,True,True,outputs=True,built=True))
        self.assertIn('readonly=on,file=/run/mpkg-fixture/built.img',transferred)
        self.assertIn('drive=outputs,serial=mpkgout0000000000004',transferred)
        with self.assertRaises(ValueError):vm.qemu_arguments(identity,False,True,True,built=True)


class FixtureConsoleTransferTests(unittest.TestCase):
    def test_decoded_script_must_match_before_execution(self):
        sys.modules.setdefault('runner',RUNNER)
        spec=importlib.util.spec_from_file_location('transfer_vm',Path(__file__).resolve().parents[1]/'scripts/fixture/vm.py')
        vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);scripts=root/'scripts';scripts.mkdir();source=scripts/'probe.sh'
            payload=b'if read -r unexpected; then exit 99; fi\nprintf executed > "$MPKG_TEST_EXECUTED"\n';source.write_bytes(payload)
            sock=mock.MagicMock();sock.recv.return_value=b''
            socket_context=mock.MagicMock();socket_context.__enter__.return_value=sock
            with mock.patch.object(RUNNER,'PROJECT',root),mock.patch.object(vm,'qmp_query',return_value={}), \
                 mock.patch.object(vm,'vm_identity',return_value={'guest_id':'00000000-0000-4000-8000-000000000000'}), \
                 mock.patch.object(vm.socket,'socket',return_value=socket_context), \
                 mock.patch.object(vm.select,'select',return_value=([sock],[],[])):
                vm.console(str(source),1)
            wire=sock.sendall.call_args.args[0].decode()
            encoded=base64.b64encode(payload).decode()
            encoded='\n'.join(encoded[i:i+76] for i in range(0,len(encoded),76))
            variants={'valid':wire,'decode':wire.replace(encoded,'!'+encoded[1:]),
                      'hash':wire.replace(encoded,base64.b64encode(b'printf wrong\n').decode())}
            fakebin=root/'bin';fakebin.mkdir();(fakebin/'stty').write_text('#!/bin/sh\nexit 0\n');(fakebin/'stty').chmod(0o755)
            for name,command in variants.items():
                destination=root/name;destination.mkdir();marker=destination/'executed'
                command=command.replace('/run/mpkg-fixture-input-',str(destination/'input-'))
                result=subprocess.run(['/usr/bin/bash','-c',command],env={'PATH':str(fakebin)+':/usr/bin:/bin',
                                      'MPKG_TEST_EXECUTED':str(marker)},input=b'protocol tail must remain unread\n',capture_output=True,timeout=10)
                self.assertEqual(marker.exists(),name=='valid',result.stdout+result.stderr)
                if name!='valid':self.assertIn(b'MPKG_TRANSFER_',result.stdout)


class FixtureHandoffTests(unittest.TestCase):
    def load(self,name):
        sys.modules['runner']=RUNNER
        directory=Path(__file__).resolve().parents[1]/'scripts/fixture'
        for dependency in ('vm','native','inputs','sources',name):
            spec=importlib.util.spec_from_file_location(dependency,directory/(dependency+'.py'))
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            sys.modules[dependency]=module
        return module

    def test_unapproved_source_directory_is_rejected_before_creation(self):
        module=self.load('source_inputs')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with mock.patch.object(module.subprocess,'check_output',return_value=str(root/'.git')+'\n'), \
                 mock.patch.object(RUNNER,'private_directory') as create:
                with self.assertRaises(ValueError):module.prepare(root/'unapproved')
                create.assert_not_called()

    def test_pending_restore_blocks_boot_and_another_snapshot(self):
        module=self.load('snapshot');vm=module.vm
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ('disk.qcow2','vars.fd'):(root/name).write_bytes(b'fixture')
            for name in ('restore-vars.pending','restore.pending.json'):
                with self.subTest(pending=name):
                    pending=root/name;pending.write_bytes(b'preserve interrupted operation')
                    with mock.patch.object(vm,'VM',root),mock.patch.object(vm,'vm_identity',return_value={}), \
                         mock.patch.object(vm,'vm_lock'),mock.patch.object(module,'create') as create, \
                         mock.patch.object(vm.subprocess,'run') as run:
                        with self.assertRaises(ValueError):vm.start(False)
                        with self.assertRaises(ValueError):module.operation('create','baseline')
                        create.assert_not_called();run.assert_not_called()
                    self.assertTrue(pending.exists());pending.unlink()


class FixtureAurBoundaryTests(unittest.TestCase):
    def load(self):
        root=Path(__file__).resolve().parents[1]
        spec=importlib.util.spec_from_file_location('core',root/'scripts/proofs/core.py')
        core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
        with mock.patch.dict(sys.modules,{'core':core}):
            spec=importlib.util.spec_from_file_location('fixture_guest_aur',root/'scripts/fixture/guest_aur.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_reading_input_does_not_treat_its_atime_change_as_drift(self):
        module=self.load()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'source';path.write_bytes(b'pinned input')
            os.utime(path,ns=(1,2))
            self.assertEqual(module.checked_file(path,root=False),b'pinned input')
            with self.assertRaises(module.Refused):module.checked_file(path,'0'*64,root=False)
            alias=Path(tmp)/'alias';alias.symlink_to(path)
            with self.assertRaises(OSError):module.checked_file(alias,root=False)

    def test_successful_exited_build_is_idle_but_running_or_transitioning_is_not(self):
        module=self.load()
        status={'MainPID':'0','ControlPID':'0','ActiveState':'active','SubState':'exited',
                'ExecMainStatus':'0','Result':'success'}
        module.require_idle_unit(status)
        for change in ({'MainPID':'12'},{'ControlPID':'13'},{'ActiveState':'activating'},
                       {'SubState':'running'},{'Result':'exit-code'}):
            with self.subTest(change=change),self.assertRaises(module.Refused):
                module.require_idle_unit(status|change)

    def test_aur_entrypoint_rejects_host_before_mutating_guest_paths_or_services(self):
        module=self.load()
        with mock.patch.object(sys,'argv',['guest_aur.py']),mock.patch.object(module,'run') as run, \
             mock.patch.object(module,'write_new') as write:
            with self.assertRaises(module.Refused):module.main()
            run.assert_not_called();write.assert_not_called()

    def test_only_the_observed_pinned_ack_url_difference_is_reconciled(self):
        module=self.load()
        pinned=('pkgbase = ack\n'
                '\tpkgdesc = A Perl-based grep replacement, aimed at programmers with large trees of heterogeneous source code\n'
                '\tpkgver = 3.10.0\n\tpkgrel = 1\n\turl = http://betterthangrep.com/\n'
                '\tarch = any\n\tlicense = GPL\n\tlicense = PerlArtistic\n'
                '\tcheckdepends = perl-yaml-pp\n\tdepends = perl-file-next\n\toptions = !emptydirs\n'
                '\tsource = https://cpan.metacpan.org/authors/id/P/PE/PETDANCE/ack-v3.10.0.tar.gz\n'
                '\tmd5sums = 424a6d5637d03f9fa8980000e0d6cbb3\n'
                '\tsha256sums = 65e83cfb38a71fca725e9a14a8201ee871e629fc6b10231e1303dd3501ba563a\n'
                '\npkgname = ack\n').encode()
        generated=pinned.replace(b'http://betterthangrep.com/',b'http://beyondgrep.com/')
        self.assertEqual(hashlib.sha256(pinned).hexdigest(),module.ACK_URL_RECONCILIATION['pinned_srcinfo_sha256'])
        self.assertEqual(hashlib.sha256(generated).hexdigest(),module.ACK_URL_RECONCILIATION['generated_srcinfo_sha256'])
        evidence=module.srcinfo_evidence('ack',module.ACK_RECIPE_COMMIT,pinned,generated)
        self.assertIs(evidence['generated_metadata_matches'],False)
        self.assertEqual(evidence['metadata_reconciliation'],module.ACK_URL_RECONCILIATION)
        for package,commit,candidate in [
            ('gitstatus',module.ACK_RECIPE_COMMIT,generated),
            ('ack','different-revision',generated),
            ('ack',module.ACK_RECIPE_COMMIT,generated.replace(b'pkgrel = 1',b'pkgrel = 2')),
            ('ack',module.ACK_RECIPE_COMMIT,generated.replace(b'depends = perl-file-next',b'depends = perl')),
            ('ack',module.ACK_RECIPE_COMMIT,generated.replace(b'beyondgrep.com',b'other.invalid')),
        ]:
            with self.subTest(package=package,commit=commit,candidate=candidate),self.assertRaises(module.Refused):
                module.srcinfo_evidence(package,commit,pinned,candidate)
        self.assertEqual(module.srcinfo_evidence('perl-file-next','pinned',pinned,pinned),
                         {'generated_metadata_matches':True})


class FixtureAurDiagnosticTests(unittest.TestCase):
    def load(self):
        root=Path(__file__).resolve().parents[1]
        spec=importlib.util.spec_from_file_location('core',root/'scripts/proofs/core.py')
        core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
        with mock.patch.dict(sys.modules,{'core':core}):
            spec=importlib.util.spec_from_file_location('fixture_aur_diagnostic',root/'scripts/fixture/guest_aur_diagnose.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_upstream_summaries_retain_each_pass_and_explicit_skip(self):
        module=self.load()
        raw=(b'compiler output omitted\nt/ack-output-color.t ........ skipped: IO::Pty not installed\n'
             b'All tests successful.\nFiles=10, Tests=100, 1 wallclock secs\nResult: PASS\n'
             b't/ack-output-color.t ........ skipped: IO::Pty not installed\n'
             b'All tests successful.\nFiles=10, Tests=100, 2 wallclock secs\nResult: PASS\n')
        result=module.test_lines(raw)
        self.assertEqual(result['matched_lines_in_window'],8)
        self.assertEqual(sum('skipped:' in item['text'] for item in result['lines']),2)
        self.assertEqual(sum(item['text']=='Result: PASS' for item in result['lines']),2)
        self.assertEqual(result['matching_lines_omitted'],0)
        self.assertNotIn('compiler',str(result))

    def test_test_output_bounds_and_partial_first_line_are_explicit(self):
        module=self.load()
        raw=b'Result: FAIL\n'+(b't/public.t ... skipped: '+b'x'*600+b'\n')*100
        result=module.test_lines(raw,prefix_omitted=True)
        self.assertEqual(result['matched_lines_in_window'],100)
        self.assertGreater(result['matching_lines_omitted'],0)
        self.assertLessEqual(sum(len(item['text'].encode()) for item in result['lines']),4096)
        self.assertTrue(all(item['line_truncated'] for item in result['lines']))
        self.assertNotIn('Result: FAIL',str(result))


class FixtureImageDiagnosticTests(unittest.TestCase):
    def load(self):
        path=Path(__file__).resolve().parents[1]/'scripts/fixture/guest_image_diagnose.py'
        # Test the pure output/query functions without importing guest entrypoints.
        program=ast.parse(path.read_text())
        nodes=[n for n in program.body if isinstance(n,ast.FunctionDef)
               and n.name in ('identity_view','expected_queries','daemon_error_summary')]
        import json
        namespace={'re':re,'json':json,'Refused':ValueError,
                   'IMAGES':(('fixture','linuxserver/sonarr','a'*64,'b'*64,'c'*64,'version'),)}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'image-diagnostic-functions','exec'),namespace)
        return namespace

    def test_image_output_excludes_configuration_labels_and_unbounded_fields(self):
        diagnostic=self.load()
        value={'Id':'sha256:'+'a'*64,'RepoTags':['public/image:tag'],
               'RepoDigests':['public/image@sha256:'+'b'*64],'Os':'linux','Architecture':'amd64',
               'Config':{'Env':['PRIVATE=must-not-emit'],'Labels':{'private':'must-not-emit'}}}
        result=diagnostic['identity_view'](value)
        self.assertEqual(set(result),{'Id','RepoTags','RepoDigests','Os','Architecture'})
        self.assertNotIn('must-not-emit',str(result))
        for altered in (dict(value,RepoTags=['x']*17),dict(value,RepoTags=['unsafe\nvalue']),
                        dict(value,Id='not-a-digest'),dict(value,Architecture='x'*33)):
            with self.assertRaises(ValueError):diagnostic['identity_view'](altered)

    def test_query_set_binds_only_original_index_and_config_identity(self):
        diagnostic=self.load()
        self.assertEqual(diagnostic['expected_queries'](),[
            {'fixture_name':'fixture','kind':'repository-index','reference':'lscr.io/linuxserver/sonarr@sha256:'+'a'*64},
            {'fixture_name':'fixture','kind':'config-digest','reference':'sha256:'+'c'*64}])

    def test_daemon_summary_emits_only_fixed_categories_and_digest_candidates(self):
        import json
        diagnostic=self.load()
        raw='\n'.join(json.dumps({'MESSAGE':message,'__REALTIME_TIMESTAMP':'123'}) for message in (
            'unrelated environment PRIVATE=must-not-emit',
            'failed to import content digest sha256:'+'a'*64+' not found PRIVATE=must-not-emit'))
        result=diagnostic['daemon_error_summary'](raw.encode())
        self.assertEqual(result['matching_events'],1)
        self.assertEqual(result['events'][0]['categories'],['missing_content_digest','import_failure'])
        self.assertEqual(result['events'][0]['content_digest_candidates'],['sha256:'+'a'*64])
        self.assertNotIn('must-not-emit',str(result))


class FixtureImageIndexPreparationTests(unittest.TestCase):
    def load(self):
        import json
        path=Path(__file__).resolve().parents[1]/'scripts/fixture/guest_image_index_prepare.py'
        program=ast.parse(path.read_text())
        names={'members','metadata','descriptor','plan','HashReader','repack'}
        nodes=[n for n in program.body if isinstance(n,(ast.Import,))
               or isinstance(n,ast.ImportFrom) and n.module=='pathlib'
               or isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names
               or isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)
               and n.targets[0].id in ('INDEX','MANIFEST','CONFIG')]
        namespace={'Refused':ValueError,'IMAGES':(),
                   'LAYERS':{'application/vnd.oci.image.layer.v1.tar+gzip'},
                   'canonical':lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode()}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'fixture-index-preparation','exec'),namespace)
        return namespace

    def fixture(self):
        module=self.load();encode=module['canonical'];digest=lambda raw:hashlib.sha256(raw).hexdigest()
        layer=b'opaque unextracted layer bytes'
        config=encode({'os':'linux','architecture':'amd64','config':{'Labels':{'org.opencontainers.image.version':'fixed'}}})
        records=[{'mediaType':module['CONFIG'],'digest':'sha256:'+digest(config),'size':len(config)},
                 {'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':'sha256:'+digest(layer),'size':len(layer)}]
        child=encode({'schemaVersion':2,'mediaType':module['MANIFEST'],'config':records[0],'layers':records[1:]})
        selected={'mediaType':module['MANIFEST'],'digest':'sha256:'+digest(child),'size':len(child),
                  'platform':{'os':'linux','architecture':'amd64'}}
        index=encode({'schemaVersion':2,'mediaType':module['INDEX'],'manifests':[selected,
                     dict(selected,digest='sha256:'+'e'*64,platform={'os':'linux','architecture':'arm64'})]})
        annotations={'org.opencontainers.image.ref.name':'lscr.io/linuxserver/test:mpkg-fixture-fixture',
                     'io.mpkg.source.index.digest':'sha256:'+digest(index)}
        old=encode({'schemaVersion':2,'mediaType':module['INDEX'],'manifests':[dict(selected,annotations=annotations)]})
        files={'oci-layout':encode({'imageLayoutVersion':'1.0.0'}),'index.json':old}
        files.update({'blobs/sha256/'+digest(raw):raw for raw in (layer,config,child,index)})
        images=(('fixture','linuxserver/test',digest(index),digest(child),digest(config),'fixed'),)
        acquired={'images':[{'fixture_name':'fixture','blobs':[
            {'digest':r['digest'],'size':r['size'],'media_type':r['mediaType']} for r in records]}]}
        return module,files,images,acquired

    def archive(self,files):
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w') as tar:
            for name,data in files.items():
                entry=tarfile.TarInfo(name);entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
        raw.seek(0)
        return raw

    def test_repack_changes_only_root_descriptors_and_preserves_all_original_blobs(self):
        import json
        module,files,images,acquired=self.fixture();prepared=io.BytesIO()
        with tarfile.open(fileobj=self.archive(files),mode='r:') as tar:
            entries=module['members'](tar);new,record=module['plan'](tar,entries,acquired,images)
            module['repack'](tar,entries,new,prepared)
        prepared.seek(0)
        with tarfile.open(fileobj=prepared,mode='r:') as tar:
            result={entry.name:tar.extractfile(entry).read() for entry in tar}
        self.assertEqual(set(result),set(files))
        self.assertEqual({n:b for n,b in result.items() if n!='index.json'},
                         {n:b for n,b in files.items() if n!='index.json'})
        top=json.loads(result['index.json'])['manifests'][0]
        self.assertEqual(top['digest'],'sha256:'+images[0][2])
        self.assertEqual(top['mediaType'],module['INDEX']);self.assertNotIn('platform',top)
        self.assertEqual(record['blob_count'],4)

    def test_repack_refuses_corrupt_layer_before_load_can_use_output(self):
        module,files,images,acquired=self.fixture()
        layer=next(n for n,b in files.items() if b==b'opaque unextracted layer bytes')
        files[layer]=b'x'*len(files[layer])
        with tarfile.open(fileobj=self.archive(files),mode='r:') as tar:
            entries=module['members'](tar);new,_=module['plan'](tar,entries,acquired,images)
            with self.assertRaises(ValueError):module['repack'](tar,entries,new,io.BytesIO())

    def test_repack_refuses_unlisted_blobs_or_changed_source_root(self):
        module,files,images,acquired=self.fixture()
        altered=dict(files);altered['blobs/sha256/'+'f'*64]=b'extra'
        with tarfile.open(fileobj=self.archive(altered),mode='r:') as tar:
            with self.assertRaises(ValueError):module['plan'](tar,module['members'](tar),acquired,images)
        altered=dict(files);altered['index.json']=files['index.json'].replace(b'linuxserver/test',b'other/repository')
        with tarfile.open(fileobj=self.archive(altered),mode='r:') as tar:
            with self.assertRaises(ValueError):module['plan'](tar,module['members'](tar),acquired,images)

    def test_archive_members_refuse_traversal_duplicates_and_links(self):
        module=self.load()
        for name,kind in (('../escape',tarfile.REGTYPE),('oci-layout',tarfile.SYMTYPE),
                          ('oci-layout',tarfile.REGTYPE)):
            raw=io.BytesIO()
            with tarfile.open(fileobj=raw,mode='w') as tar:
                entry=tarfile.TarInfo(name);entry.type=kind;entry.linkname='outside' if kind==tarfile.SYMTYPE else ''
                tar.addfile(entry,io.BytesIO())
                if kind==tarfile.REGTYPE and name=='oci-layout':tar.addfile(entry,io.BytesIO())
            raw.seek(0)
            with tarfile.open(fileobj=raw,mode='r:') as tar:
                with self.assertRaises(ValueError):module['members'](tar)


class FixtureProofAdditionTests(unittest.TestCase):
    def load(self):
        sys.modules['runner']=RUNNER
        spec=importlib.util.spec_from_file_location('fixture_addition_vm',
            Path(__file__).resolve().parents[1]/'scripts/fixture/vm.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_unlisted_target_and_changed_bytes_refuse_before_transport(self):
        module=self.load()
        with mock.patch.object(RUNNER,'regular_file') as read:
            for name in ('../docker-ready','docker_ready.py','/opt/other.py'):
                with self.assertRaises(ValueError):module.proof_install_payload(name)
            read.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'scripts/proofs').mkdir(parents=True)
            for name,filename in [('docker-ready','docker_ready.py'),('docker-baseline','docker_baseline.py'),
                                  ('native-conflict','native_conflict.py'),('service-environment','service_environment.py'),
                                  ('docker-resume','docker_resume.py'),('account-defaults','account_defaults.py'),
                                  ('native-service-recover','native_service_recover.py'),('native-service-observe','native_service_observe.py')]:
                (root/'scripts/proofs'/filename).write_bytes(b'changed reviewed source')
                with mock.patch.object(RUNNER,'PROJECT',root),mock.patch.object(module,'qmp_query') as qmp:
                    with self.assertRaises(ValueError):module.console(addition=name)
                    qmp.assert_not_called()

    def test_each_generated_addition_binds_its_own_reviewed_bytes_and_filename(self):
        module=self.load()
        expected={'service-environment':('service_environment.py','91c819c3680eb4dae50458293e191bd36ebd2c39b439dd0122dc70928e83e502'),
                  'native-service-observe':('native_service_observe.py','6f519fbc6a2fe4da2b558653cc86e9e813ad54e6586656bfd620ba1c229df5c7'),
                  'native-service-recover':('native_service_recover.py','f8e55069f53055d89c1603db90b5259e87b47129747d0bccf831053544828b3e'),
                  'account-defaults':('account_defaults.py','4d356ab3c41c8933e2030f20882ad25a3df142eb209cc5177c71f9a7b0991532'),
                  'docker-resume':('docker_resume.py','94fb8f960ee6bae8d28a958f1b9c8a54f23d83d1d98f5f174fb79630073b5f05'),
                  'docker-ready':('docker_ready.py','5efbc61753dbf873d26801f760c3e47f5a48831b1c3c0b02ba43a3c7c7e08a07'),
                  'docker-baseline':('docker_baseline.py','f6af324e2d0844a6159f0e6dcf1e72c766679953dc4e4ec5c093ff42271bbeca'),
                  'native-conflict':('native_conflict.py','5f9ba29849f9e2cdc0dcf6572bba5a4c3cc4d9abcf3a04c56ff6037d5aad7c2b')}
        for name,(filename,digest) in expected.items():
            with self.subTest(name=name):
                program=ast.parse(module.proof_install_payload(name))
                installer=next(n for n in program.body if isinstance(n,ast.FunctionDef) and n.name=='install')
                assignments={n.targets[0].id:n.value for n in ast.walk(installer)
                             if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)}
                payload=base64.b64decode(assignments['data'].args[0].value,validate=True)
                self.assertEqual(hashlib.sha256(payload).hexdigest(),digest)
                self.assertEqual(assignments['digest'].value,digest)
                self.assertEqual(assignments['target'].right.value,filename)
                self.assertEqual(assignments['record'].right.value,name+'.json')

    def test_recovery_addition_requires_both_reviewed_existing_dependencies(self):
        vm=self.load()
        program=ast.parse(vm.proof_install_payload('native-service-recover'))
        dependencies=next(n.value for n in ast.walk(program) if isinstance(n,ast.Assign)
                          and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='dependencies')
        self.assertEqual(ast.literal_eval(dependencies)['native_service_recover.py'],[
            ('account_defaults.py','4d356ab3c41c8933e2030f20882ad25a3df142eb209cc5177c71f9a7b0991532'),
            ('native_service.py','645822526f899506a9f0b6e13c27945003b111ed6d9b065e1df992095acf5961')])

    def test_generated_installer_publishes_once_without_following_existing_target(self):
        module=self.load()
        program=ast.parse(module.proof_install_payload('docker-ready'))
        definitions=ast.Module(body=[node for node in program.body
            if isinstance(node,(ast.Import,ast.ImportFrom))
            or isinstance(node,ast.FunctionDef) and node.name=='publish_new_file'],type_ignores=[])
        namespace={};exec(compile(definitions,'generated-proof-installer','exec'),namespace)
        publish=namespace['publish_new_file']
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);target=root/'docker_ready.py'
            publish(target,b'reviewed bytes')
            self.assertEqual(target.read_bytes(),b'reviewed bytes')
            self.assertEqual(target.stat().st_mode & 0o7777,0o644)
            self.assertEqual(target.stat().st_nlink,1)
            with self.assertRaises(FileExistsError):publish(target,b'overwrite')
            self.assertEqual(target.read_bytes(),b'reviewed bytes')
            alias=root/'alias';alias.symlink_to(target)
            with self.assertRaises(FileExistsError):publish(alias,b'follow symlink')
            self.assertTrue(alias.is_symlink())
            self.assertEqual(target.read_bytes(),b'reviewed bytes')


class FixtureNativeServiceReplacementTests(unittest.TestCase):
    def load(self):
        path=Path(__file__).resolve().parents[1]/'scripts/fixture/guest_native_service_replace.py'
        spec=importlib.util.spec_from_file_location('fixture_service_replacement',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_host_payload_refuses_unreviewed_replacement_before_transport(self):
        vm=FixtureProofAdditionTests().load()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'scripts/proofs').mkdir(parents=True)
            (root/'scripts/proofs/native_service.py').write_bytes(b'unreviewed')
            with mock.patch.object(RUNNER,'PROJECT',root),mock.patch.object(vm,'qmp_query') as qmp:
                with self.assertRaises(ValueError):vm.console(replacement='native-service')
                qmp.assert_not_called()
        program=ast.parse(vm.native_service_replacement_payload())
        assignment=next(n for n in program.body if isinstance(n,ast.Assign)
                        and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='REPLACEMENT_BASE64')
        self.assertEqual(hashlib.sha256(base64.b64decode(assignment.value.value)).hexdigest(),self.load().NEW_SHA256)

    def test_replacement_preserves_changed_target_and_rejects_wrong_payload(self):
        module=self.load()
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'native_service.py';target.write_bytes(b'old')
            expected=('old-identity',)
            with mock.patch.object(module,'NEW_SHA256',hashlib.sha256(b'new').hexdigest()), \
                 mock.patch.object(module,'read_bound_file',return_value=(b'old',expected)) as read:
                with self.assertRaises(RuntimeError):module.publish_replacement(target,b'wrong',expected)
                read.assert_not_called()
                read.return_value=(b'changed',('new-identity',))
                with self.assertRaises(RuntimeError):module.publish_replacement(target,b'new',expected)
                self.assertEqual(target.read_bytes(),b'old')
                read.side_effect=[(b'old',expected),(b'changed',('new-identity',))]
                with self.assertRaises(RuntimeError):module.publish_replacement(target,b'new',expected)
                self.assertEqual(target.read_bytes(),b'old')
                read.side_effect=None;read.return_value=(b'old',expected)
                module.publish_replacement(target,b'new',expected)
                self.assertEqual(target.read_bytes(),b'new')
                self.assertEqual(target.stat().st_mode & 0o7777,0o644)

    def test_bound_file_rejects_digest_drift_and_symlink_without_atime_false_positive(self):
        module=self.load();real_fstat=os.fstat
        def root_metadata(fd):
            info=real_fstat(fd)
            return SimpleNamespace(**{name:0 if name in ('st_uid','st_gid') else getattr(info,name)
                for name in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')})
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'helper.py';target.write_bytes(b'bound');target.chmod(0o644)
            os.utime(target,ns=(1,target.stat().st_mtime_ns))
            with mock.patch.object(module,'protected_directory'),mock.patch.object(module.os,'fstat',side_effect=root_metadata):
                self.assertEqual(module.read_bound_file(target,hashlib.sha256(b'bound').hexdigest())[0],b'bound')
                with self.assertRaises(RuntimeError):module.read_bound_file(target,'0'*64)
                alias=Path(tmp)/'alias';alias.symlink_to(target)
                with self.assertRaises(OSError):module.read_bound_file(alias,hashlib.sha256(b'bound').hexdigest())

    def test_existing_fixture_or_changed_unit_blocks_readonly_preflight(self):
        module=self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            previous=SimpleNamespace(**{name:root/name for name in (
                'PUBLIC','EXTERNAL_UNIT','EXCLUSIVE','SHARED','MANAGED_DROPINS')},
                state_root=lambda guest:root/'state',preflight=mock.Mock(),command=mock.Mock())
            manager=b'ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nUnitFileState=disabled\nDropInPaths=\nFragmentPath=/usr/lib/systemd/system/sshd.service\n'
            previous.command.return_value=manager
            module.require_fresh_state('guest',previous)
            previous.preflight.assert_called_once_with(root/'state')
            previous.preflight.reset_mock()
            previous.command.return_value=manager.replace(b'ControlPID=0',b'ControlPID=123')
            with self.assertRaises(RuntimeError):module.require_fresh_state('guest',previous)
            previous.preflight.assert_not_called()
            previous.command.reset_mock()
            previous.PUBLIC.symlink_to(root/'missing')
            with self.assertRaises(RuntimeError):module.require_fresh_state('guest',previous)
            previous.command.assert_not_called()


class FixtureDockerBaselineReplacementTests(unittest.TestCase):
    def load(self):
        path=Path(__file__).resolve().parents[1]/'scripts/fixture/guest_docker_baseline_replace.py'
        spec=importlib.util.spec_from_file_location('fixture_docker_replacement',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_docker_replacement_binds_current_reviewed_bytes_and_rejects_other_modes(self):
        vm=FixtureProofAdditionTests().load();module=self.load()
        program=ast.parse(vm.docker_baseline_replacement_payload())
        assignment=next(n for n in program.body if isinstance(n,ast.Assign)
                        and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='REPLACEMENT_BASE64')
        self.assertEqual(hashlib.sha256(base64.b64decode(assignment.value.value)).hexdigest(),module.NEW_SHA256)
        with mock.patch.object(vm,'qmp_query') as qmp:
            for name in ('../native-service','arbitrary.py',True):
                with self.assertRaises(ValueError):vm.console(replacement=name)
            qmp.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'scripts/proofs').mkdir(parents=True)
            (root/'scripts/proofs/docker_baseline.py').write_bytes(b'unreviewed')
            with mock.patch.object(RUNNER,'PROJECT',root),mock.patch.object(vm,'qmp_query') as qmp:
                with self.assertRaises(ValueError):vm.console(replacement='docker-baseline')
                qmp.assert_not_called()

    def test_docker_existing_state_broken_symlink_or_account_refuses_correction(self):
        module=self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with mock.patch.object(module,'Path',side_effect=lambda p:root/str(p).lstrip('/')), \
                 mock.patch.object(module.pwd,'getpwnam',side_effect=KeyError), \
                 mock.patch.object(module.pwd,'getpwuid',side_effect=KeyError), \
                 mock.patch.object(module.grp,'getgrnam',side_effect=KeyError), \
                 mock.patch.object(module.grp,'getgrgid',side_effect=KeyError) as group:
                module.require_fresh_state('guest')
                target=root/'opt/docker';target.parent.mkdir();target.symlink_to(root/'missing')
                with self.assertRaises(RuntimeError):module.require_fresh_state('guest')
                target.unlink()
                state=root/'var/lib/mpkg-proofs/guest/docker-baseline';state.mkdir(parents=True)
                with self.assertRaises(RuntimeError):module.require_fresh_state('guest')
                state.rmdir();group.side_effect=None;group.return_value=SimpleNamespace(gr_gid=962)
                with self.assertRaises(RuntimeError):module.require_fresh_state('guest')

    def test_docker_atomic_publication_refuses_old_identity_change(self):
        module=self.load()
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'docker_baseline.py';target.write_bytes(b'original')
            with mock.patch.object(module,'NEW_SHA256',hashlib.sha256(b'corrected').hexdigest()), \
                 mock.patch.object(module,'read_bound_file',return_value=(b'original',('changed',))):
                with self.assertRaises(RuntimeError):module.publish_replacement(target,b'corrected',('expected',))
            self.assertEqual(target.read_bytes(),b'original')


class FixtureNativeVerifierReplacementTests(unittest.TestCase):
    def load(self):
        path=Path(__file__).resolve().parents[1]/'scripts/fixture/guest_native_verifier_replace.py'
        spec=importlib.util.spec_from_file_location('fixture_native_verifier_replace',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_used_verifier_payload_binds_exact_reviewed_correction(self):
        vm=FixtureProofAdditionTests().load();module=self.load()
        program=ast.parse(vm.native_verifier_replacement_payload())
        assignment=next(n for n in program.body if isinstance(n,ast.Assign)
                        and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='REPLACEMENT_BASE64')
        self.assertEqual(hashlib.sha256(base64.b64decode(assignment.value.value)).hexdigest(),module.NEW_SHA256)
        self.assertEqual(module.OLD_SHA256,'645822526f899506a9f0b6e13c27945003b111ed6d9b065e1df992095acf5961')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'scripts/proofs').mkdir(parents=True)
            (root/'scripts/proofs/native_service.py').write_bytes(b'unreviewed')
            with mock.patch.object(RUNNER,'PROJECT',root),mock.patch.object(vm,'qmp_query') as qmp:
                with self.assertRaises(ValueError):vm.console(replacement='native-verifier')
                qmp.assert_not_called()

    def test_unknown_histories_and_unobserved_continuation_are_required(self):
        module=self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'native-service';root.mkdir()
            native=SimpleNamespace(state_root=lambda guest:root,MANAGED_CONFIG=Path(tmp)/'config',
                                   trusted_path=mock.Mock(),read_regular=mock.Mock(return_value=(b'{}',None)),
                                   package_baseline=mock.Mock())
            observer=SimpleNamespace(unknown_history=mock.Mock(side_effect=RuntimeError('wrong history')))
            with self.assertRaises(RuntimeError):module.observed_state('guest',native,observer)
            native.package_baseline.assert_not_called()
            observer.unknown_history.side_effect=None;observer.unknown_history.return_value=b'unchanged journal'
            with self.assertRaises(RuntimeError):module.observed_state('guest',native,observer)
            self.assertEqual(observer.unknown_history.call_args_list[-2:],[
                mock.call(root,8),mock.call(root.parent/'native-service-recovery',0)])
            native.package_baseline.assert_not_called()
            native.read_regular.reset_mock()
            (root.parent/'native-service-observation').symlink_to(Path(tmp)/'absent')
            with self.assertRaises(RuntimeError):module.observed_state('guest',native,observer)
            native.read_regular.assert_not_called()


class FixtureNativeAdoptionTests(unittest.TestCase):
    def load(self):
        root=Path(__file__).resolve().parents[1]
        spec=importlib.util.spec_from_file_location('core',root/'scripts/proofs/core.py')
        core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
        with mock.patch.dict(sys.modules,{'core':core,'native_service':SimpleNamespace(check=None,trusted_path=None)}):
            spec=importlib.util.spec_from_file_location('fixture_native_adoption',root/'scripts/fixture/guest_native_adoption.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_adoption_preserves_existing_reasons_and_adds_only_the_cli_closure(self):
        module=self.load()
        before={name:{'version':'bound','reason':'explicit'} for name in module.CLI_REQUESTS
                if name not in {'tmux','ripgrep'}}
        before['existing-dependency']={'version':'1','reason':'dependency'}
        selected=[{'name':name,'version':'frozen'} for name in sorted(module.ADDITIONS)]
        after=copy.deepcopy(before)
        after.update({p['name']:{'version':p['version'],'reason':'dependency' if p['name']=='libutempter' else 'explicit'} for p in selected})
        module.verify_result(before,after,selected)
        for name,change in [('existing-dependency',{'reason':'explicit'}),
                            ('tmux',{'version':'unfrozen'}),('libutempter',{'reason':'explicit'})]:
            altered=copy.deepcopy(after);altered[name].update(change)
            with self.subTest(name=name),self.assertRaises(module.Refused):module.verify_result(before,altered,selected)
        with self.assertRaises(module.Refused):module.verify_result(before,after|{'cmake':{'version':'extra','reason':'explicit'}},selected)

    def test_adoption_request_set_matches_the_bound_collection_without_executing_it(self):
        module=self.load();root=Path(__file__).resolve().parents[1]
        raw=(root/'vhata-cli/PKGBUILD').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),module.CLI_RECIPE_SHA256)
        body=re.search(r'depends=\((.*?)\)',raw.decode(),re.S).group(1)
        self.assertEqual(tuple(re.findall(r"'([^']+)'",body)),module.CLI_REQUESTS)


class FixtureNativeUpdateBeforeTests(unittest.TestCase):
    def load(self):
        import json
        root=Path(__file__).resolve().parents[1]
        spec=importlib.util.spec_from_file_location('core',root/'scripts/proofs/core.py')
        core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
        with mock.patch.dict(sys.modules,{'core':core,'native_manifest':SimpleNamespace(validate_build=None),
                'native_service':SimpleNamespace(check=None,trusted_path=None)}):
            spec=importlib.util.spec_from_file_location('fixture_native_update',root/'scripts/fixture/guest_native_update_before.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        source=json.loads((root/'docs/fixtures/2026-10-31-arch-native-inputs.json').read_text())
        names=set(source['resolutions']['native_change']['resolved_package_names'])|{'tmux','ripgrep','libutempter'}
        before={p['name']:{'version':p['version'],'reason':'dependency'} for p in source['repository_packages'] if p['name'] in names}
        before.update({p['package_base']:{'version':p['srcinfo_version'],'reason':'explicit' if p['package_base']=='ack' else 'dependency'}
                       for p in source['aur_packages'] if p['package_base'] in {'ack','perl-file-next'}})
        before['glibc']['reason']='explicit'  # Independently wanted existing package.
        return module,source,before

    def test_update_baseline_is_exactly220_with_old_gnupg_and_preserved_reasons(self):
        module,source,before=self.load()
        selected,expected=module.plan(source,before)
        self.assertEqual(len(before),212);self.assertEqual(len(expected),220)
        self.assertEqual({p['name'] for p in selected},module.BUILD_DEPENDENCIES)
        self.assertEqual(expected['gnupg']['version'],'2.4.9-3')
        self.assertEqual({n:expected[n] for n in before},before)
        self.assertTrue(all(expected[n]['reason']=='dependency' for n in module.BUILD_DEPENDENCIES))
        self.assertEqual(expected['gitstatus']['reason'],'explicit')
        changed=copy.deepcopy(before);changed['gnupg']['version']='2.4.9-4'
        with self.assertRaises(module.Refused):module.plan(source,changed)
        with self.assertRaises(module.Refused):module.plan(source,before|{'cmake':{'version':'unexpected','reason':'explicit'}})

    def test_update_provenance_requires_ack_false_match_and_exact_reconciliation(self):
        module,source,_=self.load();aur=FixtureAurBoundaryTests().load()
        guest='00000000-0000-4000-8000-000000000000'
        recipe=next(p for p in source['aur_packages'] if p['package_base']=='ack')
        record={'schema':1,'guest_id':guest,'package_base':'ack','recipe_commit':recipe['recipe_commit'],
                'recipe_files':{n:v['sha256_computed'] for n,v in recipe['recipe_files'].items()},
                'sources':[{'filename':s['filename'],'algorithm':a,'digest':d,'verified':True}
                           for s in recipe['sources'] for a,d in s['digests_published_in_recipe'].items()],
                'build_uid':1502,'source_verification_exit_code':0,'build_exit_code':0,
                'check_status':'passed','generated_metadata_matches':False,
                'metadata_reconciliation':dict(aur.ACK_URL_RECONCILIATION),
                'artifact':{'name':'ack','version':recipe['srcinfo_version'],'sha256':'a'*64,'size':1}}
        with mock.patch.dict(sys.modules,{'guest_aur':aur}):
            self.assertEqual(module.aur_provenance(record,source,'ack',guest),record['artifact'])
            claimed_equal=copy.deepcopy(record);claimed_equal['generated_metadata_matches']=True
            with self.assertRaises(module.Refused):module.aur_provenance(claimed_equal,source,'ack',guest)
            drift=copy.deepcopy(record);drift['metadata_reconciliation']['generated_value']='http://other.invalid/'
            with self.assertRaises(module.Refused):module.aur_provenance(drift,source,'ack',guest)


if __name__ == '__main__':unittest.main()
