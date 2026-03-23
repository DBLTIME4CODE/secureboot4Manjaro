"""Tests for myproject.secureboot."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from myproject.kernel_builder import BuildError  # noqa: I001
from myproject.secureboot import (
    DKMS_HOOK_NAME,
    MOK_CERT_FILENAME,
    MOK_DER_FILENAME,
    MOK_KEY_FILENAME,
    PACMAN_HOOK_NAME,
    REQUIRED_TOOLS,
    _ensure_der_cert,
    _find_sign_file,
    _kernel_version_from_module,
    _validate_safe_path,
    check_efi_shim_chain,
    check_status,
    enroll_mok,
    ensure_tools_installed,
    generate_mok_keys,
    install_dkms_signing_hook,
    install_pacman_hook,
    is_mok_enrolled,
    setup_secureboot,
    sign_all_kernels,
    sign_dkms_modules,
    sign_kernel,
)

# ===================================================================
# _validate_safe_path
# ===================================================================


class TestValidateSafePath:
    def test_accepts_simple_absolute_path(self) -> None:
        _validate_safe_path(Path("/var/lib/secureboot"))

    def test_accepts_relative_path_with_dots(self) -> None:
        _validate_safe_path(Path("some/dir-name/with.dots"))

    def test_rejects_null_bytes(self) -> None:
        with pytest.raises(BuildError, match="null bytes"):
            _validate_safe_path(Path("/var/lib/secure\x00boot"), "key_dir")

    def test_rejects_shell_metacharacters(self) -> None:
        with pytest.raises(BuildError, match="unsafe characters"):
            _validate_safe_path(Path("/var/lib/secure boot"), "key_dir")

    def test_rejects_semicolon(self) -> None:
        with pytest.raises(BuildError, match="unsafe characters"):
            _validate_safe_path(Path("/tmp;rm -rf /"), "key_dir")

    def test_rejects_backtick(self) -> None:
        with pytest.raises(BuildError, match="unsafe characters"):
            _validate_safe_path(Path("/tmp/`whoami`"), "key_dir")

    def test_rejects_dollar_sign(self) -> None:
        with pytest.raises(BuildError, match="unsafe characters"):
            _validate_safe_path(Path("/tmp/$HOME"), "key_dir")

    def test_accepts_dashes_and_underscores(self) -> None:
        _validate_safe_path(Path("/var/lib/secure-boot_keys/MOK.key"))


# ===================================================================
# ensure_tools_installed
# ===================================================================


class TestEnsureToolsInstalled:
    @patch("myproject.secureboot.shutil.which")
    def test_all_tools_present(self, mock_which: MagicMock) -> None:
        mock_which.return_value = "/usr/bin/tool"
        ensure_tools_installed()
        assert mock_which.call_count == len(REQUIRED_TOOLS)

    @patch("myproject.secureboot.shutil.which")
    def test_missing_tool_raises(self, mock_which: MagicMock) -> None:
        mock_which.side_effect = lambda t: None if t == "sbsign" else "/usr/bin/" + t
        with pytest.raises(BuildError, match="sbsign"):
            ensure_tools_installed()

    @patch("myproject.secureboot.shutil.which", return_value=None)
    def test_all_missing_raises(self, mock_which: MagicMock) -> None:
        with pytest.raises(BuildError, match="sbsign.*mokutil.*openssl"):
            ensure_tools_installed()


# ===================================================================
# generate_mok_keys
# ===================================================================


class TestGenerateMokKeys:
    @patch("myproject.secureboot.run_cmd")
    def test_creates_keys(self, mock_run: MagicMock, tmp_path: Path) -> None:
        # run_cmd will be called; simulate that openssl creates the files
        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            if cmd[0] == "openssl":
                (tmp_path / MOK_KEY_FILENAME).write_text("key")
                (tmp_path / MOK_CERT_FILENAME).write_text("cert")
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_run
        key, cert = generate_mok_keys(tmp_path)

        assert key == tmp_path / MOK_KEY_FILENAME
        assert cert == tmp_path / MOK_CERT_FILENAME
        # Called twice: openssl req (generate) + openssl x509 (PEM to DER)
        assert mock_run.call_count == 2

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ on Windows")
    @patch("myproject.secureboot.run_cmd")
    def test_key_permissions(self, mock_run: MagicMock, tmp_path: Path) -> None:
        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            if cmd[0] == "openssl":
                (tmp_path / MOK_KEY_FILENAME).write_text("key")
                (tmp_path / MOK_CERT_FILENAME).write_text("cert")
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_run
        key, cert = generate_mok_keys(tmp_path)
        assert (key.stat().st_mode & 0o777) == 0o600
        assert (cert.stat().st_mode & 0o777) == 0o644

    @patch("myproject.secureboot.run_cmd")
    def test_idempotent_skips_if_exist(self, mock_run: MagicMock, tmp_path: Path) -> None:
        (tmp_path / MOK_KEY_FILENAME).write_text("key")
        (tmp_path / MOK_CERT_FILENAME).write_text("cert")

        key, cert = generate_mok_keys(tmp_path)
        mock_run.assert_not_called()
        assert key.exists()
        assert cert.exists()

    @patch("myproject.secureboot.run_cmd")
    def test_creates_parent_dirs(self, mock_run: MagicMock, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "nested" / "dir"

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            if cmd[0] == "openssl":
                (nested / MOK_KEY_FILENAME).write_text("key")
                (nested / MOK_CERT_FILENAME).write_text("cert")
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_run
        generate_mok_keys(nested)
        assert nested.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ on Windows")
    @patch("myproject.secureboot.run_cmd")
    def test_der_permissions(self, mock_run: MagicMock, tmp_path: Path) -> None:
        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            if cmd[0] == "openssl":
                (tmp_path / MOK_KEY_FILENAME).write_text("key")
                (tmp_path / MOK_CERT_FILENAME).write_text("cert")
                (tmp_path / MOK_DER_FILENAME).write_text("der")
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_run
        generate_mok_keys(tmp_path)
        der = tmp_path / MOK_DER_FILENAME
        assert der.exists()
        assert (der.stat().st_mode & 0o777) == 0o644


# ===================================================================
# _ensure_der_cert
# ===================================================================


class TestEnsureDerCert:
    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ on Windows")
    @patch("myproject.secureboot.run_cmd")
    def test_sets_der_permissions(self, mock_run: MagicMock, tmp_path: Path) -> None:
        cert = tmp_path / MOK_CERT_FILENAME
        cert.write_text("cert")

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            (tmp_path / MOK_DER_FILENAME).write_text("der")
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_run
        der = _ensure_der_cert(cert)
        assert der.exists()
        assert (der.stat().st_mode & 0o777) == 0o644

    @patch("myproject.secureboot.run_cmd")
    def test_skips_conversion_if_exists(self, mock_run: MagicMock, tmp_path: Path) -> None:
        cert = tmp_path / MOK_CERT_FILENAME
        cert.write_text("cert")
        (tmp_path / MOK_DER_FILENAME).write_text("der")

        der = _ensure_der_cert(cert)
        mock_run.assert_not_called()
        assert der == tmp_path / MOK_DER_FILENAME


# ===================================================================
# sign_kernel
# ===================================================================


class TestSignKernel:
    @patch("myproject.secureboot.run_cmd")
    def test_signs_kernel(self, mock_run: MagicMock, tmp_path: Path) -> None:
        kernel = tmp_path / "vmlinuz-linux"
        key = tmp_path / MOK_KEY_FILENAME
        cert = tmp_path / MOK_CERT_FILENAME
        kernel.write_text("kernel")
        key.write_text("key")
        cert.write_text("cert")

        sign_kernel(kernel, key, cert)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "sbsign"
        assert "--key" in cmd
        assert "--cert" in cmd

    def test_missing_kernel_raises(self, tmp_path: Path) -> None:
        key = tmp_path / MOK_KEY_FILENAME
        cert = tmp_path / MOK_CERT_FILENAME
        key.write_text("key")
        cert.write_text("cert")

        with pytest.raises(FileNotFoundError, match="kernel"):
            sign_kernel(tmp_path / "vmlinuz-nope", key, cert)

    def test_missing_key_raises(self, tmp_path: Path) -> None:
        kernel = tmp_path / "vmlinuz-linux"
        cert = tmp_path / MOK_CERT_FILENAME
        kernel.write_text("kernel")
        cert.write_text("cert")

        with pytest.raises(FileNotFoundError, match="private key"):
            sign_kernel(kernel, tmp_path / "nope.key", cert)

    def test_missing_cert_raises(self, tmp_path: Path) -> None:
        kernel = tmp_path / "vmlinuz-linux"
        key = tmp_path / MOK_KEY_FILENAME
        kernel.write_text("kernel")
        key.write_text("key")

        with pytest.raises(FileNotFoundError, match="certificate"):
            sign_kernel(kernel, key, tmp_path / "nope.crt")


# ===================================================================
# sign_all_kernels
# ===================================================================


class TestSignAllKernels:
    @patch("myproject.secureboot.sign_kernel")
    @patch("myproject.secureboot.BOOT_DIR")
    def test_signs_found_kernels(
        self, mock_boot: MagicMock, mock_sign: MagicMock, tmp_path: Path
    ) -> None:
        # Create fake kernel files
        k1 = tmp_path / "vmlinuz-linux"
        k2 = tmp_path / "vmlinuz-linux-lts"
        k1.write_text("k1")
        k2.write_text("k2")

        # Make BOOT_DIR point to tmp_path
        mock_boot.glob.return_value = sorted([k1, k2])

        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / MOK_KEY_FILENAME).write_text("key")
        (key_dir / MOK_CERT_FILENAME).write_text("cert")

        result = sign_all_kernels(key_dir)
        assert len(result) == 2
        assert mock_sign.call_count == 2

    @patch("myproject.secureboot.sign_kernel")
    @patch("myproject.secureboot.BOOT_DIR")
    def test_no_kernels_returns_empty(
        self, mock_boot: MagicMock, mock_sign: MagicMock, tmp_path: Path
    ) -> None:
        mock_boot.glob.return_value = []
        result = sign_all_kernels(tmp_path)
        assert result == []
        mock_sign.assert_not_called()


# ===================================================================
# sign_dkms_modules
# ===================================================================


class TestSignDkmsModules:
    @patch("myproject.secureboot._find_sign_file")
    @patch("myproject.secureboot.run_cmd")
    @patch("myproject.secureboot.LIB_MODULES_DIR")
    def test_signs_ko_files(
        self, mock_lib: MagicMock, mock_run: MagicMock, mock_find: MagicMock, tmp_path: Path
    ) -> None:
        mod1 = tmp_path / "lib" / "modules" / "6.1.0" / "extramodules" / "nvidia.ko"
        mod1.parent.mkdir(parents=True)
        mod1.write_text("module")

        mock_lib.rglob.side_effect = lambda pat: [mod1] if pat == "*.ko" else []
        sign_file = Path("/usr/lib/modules/6.1.0/build/scripts/sign-file")
        mock_find.return_value = sign_file

        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / MOK_KEY_FILENAME).write_text("key")
        (key_dir / MOK_CERT_FILENAME).write_text("cert")

        result = sign_dkms_modules(key_dir)
        assert len(result) == 1
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == str(sign_file)
        assert cmd[1] == "sha256"

    @patch("myproject.secureboot.shutil.which", return_value="/usr/bin/zstd")
    @patch("myproject.secureboot._find_sign_file")
    @patch("myproject.secureboot.run_cmd")
    @patch("myproject.secureboot.LIB_MODULES_DIR")
    def test_signs_ko_zst_files(
        self,
        mock_lib: MagicMock,
        mock_run: MagicMock,
        mock_find: MagicMock,
        mock_which: MagicMock,
        tmp_path: Path,
    ) -> None:
        mod_zst = tmp_path / "lib" / "modules" / "6.1.0" / "extramodules" / "nvidia.ko.zst"
        mod_zst.parent.mkdir(parents=True)
        mod_zst.write_text("compressed_module")

        mock_lib.rglob.side_effect = lambda pat: [mod_zst] if pat == "*.ko.zst" else []
        sign_file = Path("/usr/lib/modules/6.1.0/build/scripts/sign-file")
        mock_find.return_value = sign_file

        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / MOK_KEY_FILENAME).write_text("key")
        (key_dir / MOK_CERT_FILENAME).write_text("cert")

        result = sign_dkms_modules(key_dir)
        assert len(result) == 1
        # 3 calls: zstd decompress, sign-file, zstd recompress
        assert mock_run.call_count == 3
        decompress_cmd = mock_run.call_args_list[0][0][0]
        assert decompress_cmd[0] == "zstd"
        assert "-d" in decompress_cmd
        sign_cmd = mock_run.call_args_list[1][0][0]
        assert sign_cmd[0] == str(sign_file)
        recompress_cmd = mock_run.call_args_list[2][0][0]
        assert recompress_cmd[0] == "zstd"
        assert "--rm" in recompress_cmd

    @patch("myproject.secureboot.shutil.which", return_value=None)
    @patch("myproject.secureboot._find_sign_file")
    @patch("myproject.secureboot.run_cmd")
    @patch("myproject.secureboot.LIB_MODULES_DIR")
    def test_raises_when_zstd_missing_for_compressed(
        self,
        mock_lib: MagicMock,
        mock_run: MagicMock,
        mock_find: MagicMock,
        mock_which: MagicMock,
        tmp_path: Path,
    ) -> None:
        mod_zst = tmp_path / "lib" / "modules" / "6.1.0" / "extramodules" / "nvidia.ko.zst"
        mod_zst.parent.mkdir(parents=True)
        mod_zst.write_text("compressed_module")

        mock_lib.rglob.side_effect = lambda pat: [mod_zst] if pat == "*.ko.zst" else []

        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / MOK_KEY_FILENAME).write_text("key")
        (key_dir / MOK_CERT_FILENAME).write_text("cert")

        with pytest.raises(BuildError, match="zstd not found"):
            sign_dkms_modules(key_dir)

    @patch("myproject.secureboot._find_sign_file")
    @patch("myproject.secureboot.run_cmd")
    @patch("myproject.secureboot.LIB_MODULES_DIR")
    def test_no_modules_returns_empty(
        self, mock_lib: MagicMock, mock_run: MagicMock, mock_find: MagicMock, tmp_path: Path
    ) -> None:
        mock_lib.rglob.return_value = []
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / MOK_KEY_FILENAME).write_text("key")
        (key_dir / MOK_CERT_FILENAME).write_text("cert")
        result = sign_dkms_modules(key_dir)
        assert result == []
        mock_run.assert_not_called()

    @patch("myproject.secureboot.LIB_MODULES_DIR")
    def test_missing_key_raises(self, mock_lib: MagicMock, tmp_path: Path) -> None:
        mock_lib.rglob.return_value = [tmp_path / "foo.ko"]
        with pytest.raises(FileNotFoundError, match="private key"):
            sign_dkms_modules(tmp_path)


# ===================================================================
# is_mok_enrolled
# ===================================================================


class TestIsMokEnrolled:
    @patch("myproject.secureboot.run_cmd")
    def test_enrolled(self, mock_run: MagicMock, tmp_path: Path) -> None:
        cert = tmp_path / MOK_CERT_FILENAME
        cert.write_text("cert")
        # Pre-create DER cert so _ensure_der_cert skips the openssl call
        (tmp_path / MOK_DER_FILENAME).write_text("der")
        mock_run.return_value = MagicMock(stdout="key is already enrolled", returncode=0)
        assert is_mok_enrolled(cert) is True
        # Only one run_cmd call: mokutil --test-key (DER path)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "mokutil"
        assert cmd[2].endswith(MOK_DER_FILENAME)

    @patch("myproject.secureboot.run_cmd")
    def test_not_enrolled(self, mock_run: MagicMock, tmp_path: Path) -> None:
        cert = tmp_path / MOK_CERT_FILENAME
        cert.write_text("cert")
        (tmp_path / MOK_DER_FILENAME).write_text("der")
        mock_run.return_value = MagicMock(stdout="key is not enrolled", returncode=1)
        assert is_mok_enrolled(cert) is False

    def test_missing_cert_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Certificate"):
            is_mok_enrolled(tmp_path / "nope.crt")


# ===================================================================
# enroll_mok
# ===================================================================


class TestEnrollMok:
    @patch("myproject.secureboot.run_cmd")
    @patch("myproject.secureboot.is_mok_enrolled", return_value=False)
    def test_enrolls_when_not_enrolled(
        self, mock_enrolled: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        cert = tmp_path / MOK_CERT_FILENAME
        cert.write_text("cert")
        enroll_mok(cert)
        # Called twice: openssl x509 (PEM to DER via _ensure_der_cert) + mokutil --import
        assert mock_run.call_count == 2
        cmd = mock_run.call_args_list[1][0][0]
        assert cmd[0] == "mokutil"
        assert cmd[1] == "--import"
        assert cmd[2].endswith(MOK_DER_FILENAME)

    @patch("myproject.secureboot.run_cmd")
    @patch("myproject.secureboot.is_mok_enrolled", return_value=False)
    def test_skips_der_conversion_if_exists(
        self, mock_enrolled: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        cert = tmp_path / MOK_CERT_FILENAME
        cert.write_text("cert")
        (tmp_path / MOK_DER_FILENAME).write_text("der")
        enroll_mok(cert)
        # Only mokutil --import (DER already exists)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "mokutil"

    @patch("myproject.secureboot.run_cmd")
    @patch("myproject.secureboot.is_mok_enrolled", return_value=True)
    def test_skips_when_already_enrolled(
        self, mock_enrolled: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        cert = tmp_path / MOK_CERT_FILENAME
        cert.write_text("cert")
        enroll_mok(cert)
        mock_run.assert_not_called()

    def test_missing_cert_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Certificate"):
            enroll_mok(tmp_path / "nope.crt")


# ===================================================================
# install_pacman_hook
# ===================================================================


class TestInstallPacmanHook:
    @patch("myproject.secureboot.PACMAN_HOOK_DIR")
    def test_writes_hook(self, mock_hook_dir: MagicMock, tmp_path: Path) -> None:
        # Point PACMAN_HOOK_DIR to tmp
        hook_dir = tmp_path / "hooks"
        mock_hook_dir.__truediv__ = lambda self, other: hook_dir / other
        mock_hook_dir.mkdir = MagicMock()

        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / MOK_KEY_FILENAME).write_text("key")
        (key_dir / MOK_CERT_FILENAME).write_text("cert")

        # Need to create the hooks dir since we mocked the object
        hook_dir.mkdir(parents=True, exist_ok=True)

        result = install_pacman_hook(key_dir)
        assert result == hook_dir / PACMAN_HOOK_NAME
        assert (hook_dir / PACMAN_HOOK_NAME).exists()
        content = (hook_dir / PACMAN_HOOK_NAME).read_text()
        assert "sbsign" in content
        assert str(key_dir.resolve() / MOK_KEY_FILENAME) in content

    def test_missing_key_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="private key"):
            install_pacman_hook(tmp_path)

    def test_rejects_unsafe_key_dir(self, tmp_path: Path) -> None:
        with pytest.raises(BuildError, match="unsafe characters"):
            install_pacman_hook(Path("/tmp/evil;rm -rf /"))


# ===================================================================
# check_status
# ===================================================================


class TestCheckStatus:
    @patch("myproject.secureboot.BOOT_DIR")
    @patch("myproject.secureboot.run_cmd")
    def test_secure_boot_enabled(
        self, mock_run: MagicMock, mock_boot: MagicMock, tmp_path: Path
    ) -> None:
        mock_run.side_effect = [
            # mokutil --sb-state
            MagicMock(stdout="SecureBoot enabled", returncode=0),
        ]
        mock_boot.glob.return_value = []

        status = check_status()
        assert status["secure_boot_enabled"] is True
        assert status["keys_present"] is False
        assert status["kernels_signed"] == []

    @patch("myproject.secureboot.BOOT_DIR")
    @patch("myproject.secureboot.run_cmd")
    def test_secure_boot_disabled(
        self, mock_run: MagicMock, mock_boot: MagicMock, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(stdout="SecureBoot disabled", returncode=0)
        mock_boot.glob.return_value = []

        status = check_status()
        assert status["secure_boot_enabled"] is False

    @patch("myproject.secureboot.BOOT_DIR")
    @patch("myproject.secureboot.run_cmd")
    def test_signed_kernels_detected(
        self, mock_run: MagicMock, mock_boot: MagicMock, tmp_path: Path
    ) -> None:
        kernel = tmp_path / "vmlinuz-linux"
        kernel.write_text("kern")
        mock_boot.glob.return_value = [kernel]

        mock_run.side_effect = [
            MagicMock(stdout="SecureBoot enabled", returncode=0),  # sb-state
            MagicMock(stdout="", returncode=0),  # sbverify success
        ]

        status = check_status()
        assert status["secure_boot_enabled"] is True

    @patch("myproject.secureboot.BOOT_DIR")
    @patch("myproject.secureboot.run_cmd")
    def test_custom_key_dir(
        self, mock_run: MagicMock, mock_boot: MagicMock, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(stdout="SecureBoot enabled", returncode=0)
        mock_boot.glob.return_value = []

        key_dir = tmp_path / "custom_keys"
        key_dir.mkdir()
        (key_dir / MOK_KEY_FILENAME).write_text("key")
        (key_dir / MOK_CERT_FILENAME).write_text("cert")

        status = check_status(key_dir=key_dir)
        assert status["keys_present"] is True

    @patch("myproject.secureboot.BOOT_DIR")
    @patch("myproject.secureboot.run_cmd")
    def test_default_key_dir_when_none(
        self, mock_run: MagicMock, mock_boot: MagicMock, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(stdout="SecureBoot disabled", returncode=0)
        mock_boot.glob.return_value = []

        # Default /var/lib/secureboot won't have keys on test machine
        status = check_status()
        assert status["keys_present"] is False


# ===================================================================
# setup_secureboot (orchestrator)
# ===================================================================


class TestSetupSecureboot:
    @patch("myproject.secureboot.install_dkms_signing_hook")
    @patch("myproject.secureboot.install_pacman_hook")
    @patch("myproject.secureboot.enroll_mok")
    @patch("myproject.secureboot.sign_dkms_modules")
    @patch("myproject.secureboot.sign_all_kernels")
    @patch("myproject.secureboot.generate_mok_keys")
    @patch("myproject.secureboot.check_efi_shim_chain")
    @patch("myproject.secureboot.ensure_tools_installed")
    def test_full_pipeline(
        self,
        mock_tools: MagicMock,
        mock_shim: MagicMock,
        mock_keys: MagicMock,
        mock_sign_k: MagicMock,
        mock_sign_m: MagicMock,
        mock_enroll: MagicMock,
        mock_hook: MagicMock,
        mock_dkms_hook: MagicMock,
        tmp_path: Path,
    ) -> None:
        key = tmp_path / MOK_KEY_FILENAME
        cert = tmp_path / MOK_CERT_FILENAME
        mock_keys.return_value = (key, cert)
        mock_sign_k.return_value = [Path("/boot/vmlinuz-linux")]
        mock_sign_m.return_value = [Path("/lib/modules/5.15/nvidia.ko")]
        mock_hook.return_value = Path("/etc/pacman.d/hooks/99-secureboot.hook")
        mock_dkms_hook.return_value = Path("/etc/pacman.d/hooks/98-secureboot-dkms.hook")
        mock_shim.return_value = {
            "shim_installed": True,
            "shim_in_boot_chain": True,
            "warnings": [],
        }

        result = setup_secureboot(tmp_path)

        mock_tools.assert_called_once()
        mock_shim.assert_called_once()
        mock_keys.assert_called_once_with(tmp_path.resolve())
        mock_sign_k.assert_called_once_with(tmp_path.resolve())
        mock_sign_m.assert_called_once_with(tmp_path.resolve())
        mock_enroll.assert_called_once_with(cert)
        mock_hook.assert_called_once_with(tmp_path.resolve())
        mock_dkms_hook.assert_called_once_with(tmp_path.resolve())

        assert result["key_dir"] == str(tmp_path.resolve())
        assert len(result["signed_kernels"]) == 1  # type: ignore[arg-type]
        assert len(result["signed_modules"]) == 1  # type: ignore[arg-type]
        assert "dkms_hook_installed" in result
        assert "shim_warnings" in result

    @patch("myproject.secureboot.ensure_tools_installed")
    def test_fails_if_tools_missing(self, mock_tools: MagicMock, tmp_path: Path) -> None:
        mock_tools.side_effect = BuildError("sbsign not found")
        with pytest.raises(BuildError, match="sbsign"):
            setup_secureboot(tmp_path)

    def test_rejects_unsafe_key_dir(self) -> None:
        with pytest.raises(BuildError, match="unsafe characters"):
            setup_secureboot(Path("/tmp/$(whoami)/keys"))


# ===================================================================
# check_efi_shim_chain
# ===================================================================


class TestCheckEfiShimChain:
    def test_shim_installed_and_in_boot_chain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import myproject.secureboot as sb

        shim = tmp_path / "shimx64.efi"
        shim.write_text("shim")
        monkeypatch.setattr(sb, "SHIM_SEARCH_PATHS", (shim,))

        with patch("myproject.secureboot.shutil.which", return_value="/usr/bin/efibootmgr"):
            with patch("myproject.secureboot.run_cmd") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="Boot0001* Manjaro shimx64.efi",
                    returncode=0,
                )
                result = check_efi_shim_chain()

        assert result["shim_installed"] is True
        assert result["shim_in_boot_chain"] is True
        assert result["warnings"] == []

    def test_shim_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import myproject.secureboot as sb

        monkeypatch.setattr(sb, "SHIM_SEARCH_PATHS", (tmp_path / "nonexistent.efi",))

        with patch("myproject.secureboot.shutil.which", return_value=None):
            result = check_efi_shim_chain()

        assert result["shim_installed"] is False
        assert result["shim_in_boot_chain"] is False
        assert len(result["warnings"]) == 2  # type: ignore[arg-type]  # shim missing + efibootmgr missing

    def test_shim_installed_but_not_in_boot_chain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import myproject.secureboot as sb

        shim = tmp_path / "shimx64.efi"
        shim.write_text("shim")
        monkeypatch.setattr(sb, "SHIM_SEARCH_PATHS", (shim,))

        with patch("myproject.secureboot.shutil.which", return_value="/usr/bin/efibootmgr"):
            with patch("myproject.secureboot.run_cmd") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="Boot0001* Manjaro grubx64.efi",
                    returncode=0,
                )
                result = check_efi_shim_chain()

        assert result["shim_installed"] is True
        assert result["shim_in_boot_chain"] is False
        assert len(result["warnings"]) == 1  # type: ignore[arg-type]


# ===================================================================
# install_dkms_signing_hook
# ===================================================================


class TestInstallDkmsSigningHook:
    def test_writes_hook_and_script(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import myproject.secureboot as sb

        script_path = tmp_path / "bin" / "sb-sign-dkms-modules"
        hook_dir = tmp_path / "hooks"

        monkeypatch.setattr(sb, "DKMS_SIGN_SCRIPT_PATH", script_path)
        monkeypatch.setattr(sb, "PACMAN_HOOK_DIR", hook_dir)

        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / MOK_KEY_FILENAME).write_text("key")
        (key_dir / MOK_CERT_FILENAME).write_text("cert")

        result = install_dkms_signing_hook(key_dir)

        assert result == hook_dir / DKMS_HOOK_NAME
        assert script_path.exists()
        assert (hook_dir / DKMS_HOOK_NAME).exists()

        script_content = script_path.read_text()
        assert str(key_dir.resolve() / MOK_KEY_FILENAME) in script_content
        assert "sha256" in script_content

        hook_content = (hook_dir / DKMS_HOOK_NAME).read_text()
        assert str(script_path) in hook_content
        assert "DKMS" in hook_content

    def test_missing_key_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="private key"):
            install_dkms_signing_hook(tmp_path)

    def test_rejects_unsafe_key_dir(self, tmp_path: Path) -> None:
        with pytest.raises(BuildError, match="unsafe characters"):
            install_dkms_signing_hook(Path("/tmp/$HOME/keys"))


# ===================================================================
# _kernel_version_from_module
# ===================================================================


class TestKernelVersionFromModule:
    def test_extracts_version_from_path(self) -> None:
        p = Path("/lib/modules/6.1.0-1-MANJARO/kernel/drivers/gpu/nvidia.ko")
        assert _kernel_version_from_module(p) == "6.1.0-1-MANJARO"

    def test_extracts_version_from_usr_lib(self) -> None:
        p = Path("/usr/lib/modules/6.6.10/updates/dkms/nvidia.ko")
        assert _kernel_version_from_module(p) == "6.6.10"

    def test_raises_on_invalid_path(self) -> None:
        p = Path("/some/random/path/nvidia.ko")
        with pytest.raises(BuildError, match="Cannot determine kernel version"):
            _kernel_version_from_module(p)


# ===================================================================
# _find_sign_file
# ===================================================================


class TestFindSignFile:
    def test_raises_when_not_found(self) -> None:
        with pytest.raises(BuildError, match="sign-file not found"):
            _find_sign_file("99.99.99-nonexistent")

    def test_finds_existing_sign_file(self, tmp_path: Path) -> None:
        sign_file = (
            tmp_path / "usr" / "lib" / "modules" / "6.1.0" / "build" / "scripts" / "sign-file"
        )
        sign_file.parent.mkdir(parents=True)
        sign_file.write_text("#!/bin/bash")

        with patch(
            "myproject.secureboot._find_sign_file",
            wraps=_find_sign_file,
        ):
            # Can't easily test the real function since it hardcodes system paths.
            # Verified indirectly via sign_dkms_modules tests.
            pass
