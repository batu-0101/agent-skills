"""Real Windows symlink/junction and pathname-swap acceptance."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Native Windows handle semantics')
if os.name == 'nt':
    from eval_runner import windows_safety as native
    from eval_runner.path_safety import hash_contained_file
    from eval_runner.sandbox import cleanup_sandbox, stage_baseline_sandbox


def junction(link, target):
    # All arguments are generated isolated fixture paths, never caller input.
    result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(target)],
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    assert link.is_junction()


def test_regular_hash_and_absent_nonfile():
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder); (root/'data').mkdir(); (root/'data/item').write_bytes(b'handle-native')
        assert hash_contained_file(root, 'data/item') == hashlib.sha256(b'handle-native').hexdigest()[:16]
        assert hash_contained_file(root, 'absent') is None
        assert hash_contained_file(root, 'data') is None
        with pytest.raises(FileNotFoundError): hash_contained_file(root/'absent-root', 'item')


def test_hash_rejects_windows_aliases_and_ads():
    with tempfile.TemporaryDirectory() as folder:
        for name in ['file:secret', 'NUL', 'AUX.txt', 'file.', 'file ', 'x'*256]:
            with pytest.raises(ValueError):
                hash_contained_file(Path(folder), name)


def test_hash_rejects_directory_junction():
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)/'root'; root.mkdir(); outside=Path(folder)/'outside'; outside.mkdir()
        (outside/'secret').write_text('outside'); junction(root/'link', outside)
        with pytest.raises(ValueError): hash_contained_file(root, 'link/secret')


def test_hashing_rejects_validation_to_open_symlink_swap():
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)/'root'; root.mkdir(); fixture=root/'fixture.txt'; fixture.write_text('safe')
        outside=Path(folder)/'secret'; outside.write_text('outside')
        original=native._open_relative; swapped=False
        def swap(parent, name, access=native.READ):
            nonlocal swapped
            if name=='fixture.txt' and not swapped:
                fixture.unlink(); fixture.symlink_to(outside); swapped=True
            return original(parent, name, access)
        with patch.object(native, '_open_relative', swap):
            with pytest.raises(ValueError): hash_contained_file(root, 'fixture.txt')
        assert swapped and outside.read_text()=='outside'


def test_hash_rejects_directory_junction_swap():
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)/'root'; root.mkdir(); directory=root/'data'; directory.mkdir(); (directory/'item').write_text('safe')
        outside=Path(folder)/'outside'; outside.mkdir(); (outside/'item').write_text('outside')
        original=native._open_relative; swapped=False
        def swap(parent, name, access=native.READ):
            nonlocal swapped
            if name=='data' and not swapped:
                directory.rename(root/'moved'); junction(directory, outside); swapped=True
            return original(parent, name, access)
        with patch.object(native, '_open_relative', swap):
            with pytest.raises(ValueError): hash_contained_file(root, 'data/item')
        assert swapped and (outside/'item').read_text()=='outside'


def test_open_handle_prevents_file_replacement():
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder); fixture=root/'item'; fixture.write_bytes(b'safe')
        original=native._open_relative; blocked=[]
        def replace_after_open(parent, name, access=native.READ):
            handle=original(parent, name, access)
            try:
                if name=='item':
                    with pytest.raises(PermissionError): fixture.rename(root/'moved')
                    blocked.append(True)
                return handle
            except BaseException:
                native.K.CloseHandle(handle); raise
        with patch.object(native, '_open_relative', replace_after_open):
            assert hash_contained_file(root, 'item')==hashlib.sha256(b'safe').hexdigest()[:16]
        assert blocked


def test_cleanup_unlinks_nested_junction_without_touching_target():
    with tempfile.TemporaryDirectory() as folder:
        outside=Path(folder)/'outside'; outside.mkdir(); victim=outside/'victim'; victim.write_text('preserve')
        before=victim.stat().st_mode; staged=stage_baseline_sandbox(Path('skill'))
        junction(staged/'link', outside)
        cleanup_sandbox(staged)
        assert not staged.parent.exists() and victim.read_text()=='preserve' and victim.stat().st_mode==before


def test_cleanup_race_replaces_nested_directory_with_junction():
    with tempfile.TemporaryDirectory() as folder:
        outside=Path(folder)/'outside'; outside.mkdir(); victim=outside/'victim'; victim.write_text('preserve')
        before=outside.stat().st_mode; staged=stage_baseline_sandbox(Path('skill'))
        child=staged/'child'; child.mkdir(); (child/'owned').write_text('owned')
        original=native._open_relative; swapped=False
        def swap(parent, name, access=native.READ):
            nonlocal swapped
            if name=='child' and not swapped:
                child.rename(staged/'moved'); junction(child, outside); swapped=True
            return original(parent, name, access)
        with patch.object(native, '_open_relative', swap): cleanup_sandbox(staged)
        assert swapped and not staged.parent.exists()
        assert victim.read_text()=='preserve' and outside.stat().st_mode==before


def test_cleanup_root_replacement_junction_preserves_external_tree():
    with tempfile.TemporaryDirectory() as folder:
        outside=Path(folder)/'outside'; outside.mkdir(); victim=outside/'victim'; victim.write_text('preserve')
        staged=stage_baseline_sandbox(Path('skill')); root=staged.parent; moved=root.with_name(root.name+'-moved')
        root.rename(moved); junction(root,outside)
        cleanup_sandbox(staged)
        assert not root.exists() and victim.read_text()=='preserve'
        cleanup_sandbox(moved/'skill')


def test_cleanup_rejects_unowned_scope():
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder); victim=root/'victim'; victim.write_text('preserve')
        with pytest.raises(ValueError): cleanup_sandbox(root/'imaginary-child')
        assert victim.read_text()=='preserve'


def test_cleanup_preserves_external_readonly_hardlink_attributes():
    with tempfile.TemporaryDirectory() as folder:
        victim=Path(folder)/'victim';victim.write_text('preserve');victim.chmod(0o444)
        original=victim.stat().st_file_attributes
        staged=stage_baseline_sandbox(Path('skill'));os.link(victim,staged/'hard-link')
        try:
            cleanup_sandbox(staged)
            assert not staged.parent.exists()
            assert victim.read_text()=='preserve'
            assert victim.stat().st_file_attributes==original
        finally:
            victim.chmod(0o600)
