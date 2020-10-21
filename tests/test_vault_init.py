import os
import sys
import gpg
import tempfile
import time
import hvac
import random
import docker
import pytest
import vault_init
import requests
import string
import urllib.parse

from gpg.core import Context as _Context
from gpg.gpgme import GPGME_DELETE_ALLOW_SECRET, GPGME_DELETE_FORCE, gpgme_op_delete_ext

DOCKER_TIMEOUT = 3 * 60

@pytest.fixture
def tempdir():
    with tempfile.TemporaryDirectory(prefix="pytest_", suffix="_gpg") as directory:
        yield str(directory)

@pytest.fixture(scope="session")
def vault_image():
    client = docker.from_env()
    image_before = False
    try:
        image = client.images.get("vault:latest")
        image_before = image is not None
    except docker.errors.ImageNotFound:
        image = client.images.pull("vault:latest")
    yield image
    if not image_before:
        client.images.remove(image.id)        

@pytest.fixture(autouse=True, scope="function")
def _auto_gpg_context(monkeypatch, tempdir):
    class GpgContextManager():
        instance = None
        def __init__(self, *args, **kwargs):
            GpgContextManager.instance.armor = kwargs.get("armor", GpgContextManager.instance.armor)
            GpgContextManager.instance.textmode  = kwargs.get("textmode ", GpgContextManager.instance.textmode)
            GpgContextManager.instance.offline  = kwargs.get("offline", GpgContextManager.instance.offline)
            GpgContextManager.instance.signers   = kwargs.get("signers", GpgContextManager.instance.signers)
            GpgContextManager.instance.pinentry_mode  = kwargs.get("pinentry_mode", GpgContextManager.instance.pinentry_mode)
            GpgContextManager.instance.protocol  = kwargs.get("protocol", GpgContextManager.instance.protocol)
            GpgContextManager.instance.home_dir  = kwargs.get("home_dir", GpgContextManager.instance.home_dir)

        def __enter__(self):
            return GpgContextManager.instance
        def __exit__(self, type, value, tb):
            pass

    with _Context(offline=True, home_dir=tempdir) as ctx:
        GpgContextManager.instance = ctx
        monkeypatch.setattr(gpg, "Context", GpgContextManager)
        yield


@pytest.fixture
def random_userid():
    def _random_userid():
        while True:
            yield ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    yield _random_userid()

@pytest.fixture
def random_hex():
    def _random_hex():
        while True:
            yield ''.join(random.choice([c for c in "0123456789abcedf"]) for i in range(66))
    yield _random_hex()

@pytest.fixture
def mock_full_env_vault(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://monkeyhost:8200")
    monkeypatch.setenv("VAULT_KEY_SHARE", "2")
    monkeypatch.setenv("VAULT_KEY_THRESHOLD", "1")
    monkeypatch.setenv("VAULT_KEYS_GPG_1", "-- ENV KEYS PGP 1 --")
    monkeypatch.setenv("VAULT_KEYS_GPG_2", "-- ENV KEYS PGP 2 --")
    monkeypatch.setenv("VAULT_ROOT_TOKEN_GPG", "-- ROOT PGP --")
    monkeypatch.setenv("VAULT_UNSEALKEY_1", "test_env_keys1")
    monkeypatch.setenv("VAULT_UNSEALKEY_2", "test_env_keys2")

@pytest.fixture
def mock_full_env_missing_one_gpgs_vault(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://monkeyhost:8200")
    monkeypatch.setenv("VAULT_KEY_SHARE", "2")
    monkeypatch.setenv("VAULT_KEY_THRESHOLD", "1")
    monkeypatch.setenv("VAULT_KEYS_GPG_1", "-- ENV KEYS PGP 1 --")
    monkeypatch.setenv("VAULT_ROOT_TOKEN_GPG", "-- ROOT PGP --")
    monkeypatch.setenv("VAULT_UNSEALKEY_1", "test_env_keys1")
    monkeypatch.setenv("VAULT_UNSEALKEY_2", "test_env_keys2")

@pytest.fixture
def mock_unseal_env_vault(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://monkeyhost:8200")
    monkeypatch.setenv("VAULT_UNSEALKEY_1", "test_env_keys1")
    monkeypatch.setenv("VAULT_UNSEALKEY_2", "test_env_keys2")

@pytest.fixture
def full_cli_args():
    return [
        "--vault_addr=http://clihost:8200",
        "--key_share=3",
        "--key_threshold=2",
        "--gpgs=-- CLI KEYS PGP 1 --",
        "--gpgs=-- CLI KEYS PGP 2 --",
        "--gpgs=-- CLI KEYS PGP 3 --",
        "--root_token_gpg=-- CLI ROOT PGP --",
        "--keys=test_cli_keys1",
        "--keys=test_cli_keys2"
    ]

@pytest.fixture
def full_cli_missing_one_gpgs_args():
    return [
        "--vault_addr=http://clihost:8200",
        "--key_share=3",
        "--key_threshold=2",
        "--gpgs=-- CLI KEYS PGP 1 --",
        "--gpgs=-- CLI KEYS PGP 2 --",
        "--root_token_gpg=-- CLI ROOT PGP --",
        "--keys=test_cli_keys1",
        "--keys=test_cli_keys2"
    ]

@pytest.fixture
def unseal_cli_args():
    return [
        "--vault_addr=http://clihost:8200",
        "--keys=test_cli_keys1",
        "--keys=test_cli_keys2"
    ]

@pytest.fixture
def single_temp_key(random_userid):
    with gpg.Context(armor=True) as gpg_context:
        with gpg.Data() as expkey:
            dmkey = gpg_context.create_key(algorithm="rsa1024", userid=next(random_userid), encrypt=True)
            gpg_context.op_export(dmkey.fpr, 0, expkey)
            expkey.seek(0, os.SEEK_SET)
            yield expkey.read()

@pytest.fixture
def five_temp_wrong_key(random_userid):
    keys = []
    with gpg.Context(armor=True) as gpg_context:
        for _ in range(0,5):
            with gpg.Data() as expkey:
                dmkey = gpg_context.create_key(algorithm="rsa1024", userid=next(random_userid), encrypt=False)
                gpg_context.op_export(dmkey.fpr, 0, expkey)
                expkey.seek(0, os.SEEK_SET)
                keys.append(expkey.read())
    yield keys

@pytest.fixture
def five_temp_key(random_userid):
    keys = []
    with gpg.Context(armor=True) as gpg_context:
        for _ in range(0,5):
            with gpg.Data() as expkey:
                dmkey = gpg_context.create_key(algorithm="rsa1024", userid=next(random_userid), encrypt=True)
                gpg_context.op_export(dmkey.fpr, 0, expkey)
                expkey.seek(0, os.SEEK_SET)
                keys.append(expkey.read())
    yield keys

@pytest.fixture
def vault_server(vault_image, request):
    vault_config = """
    {
        "listener": [{
            "tcp": {
                "address" : "0.0.0.0:8200",
                "tls_disable" : 1
            }
        }],
        "storage": {
            "inmem": {}
        },
        "ui":true
    }
    """
    env = {
        "VAULT_LOCAL_CONFIG":vault_config
    }
    client = docker.from_env()
    port = random.randint(10000,20000)
    _command = f"timeout {DOCKER_TIMEOUT} docker-entrypoint.sh server"
    container = client.containers.run(vault_image.id, name=request.node.name, detach=True, command=_command, cap_add="IPC_LOCK", environment=env, remove=True, ports={'8200/tcp':port})
    container_id = container.id
    
    _address = urllib.parse.urlparse(client.api.base_url).netloc.split(":")[0]
    max_wait_time = 5
    while True:
        if max_wait_time < 0:
            raise ConnectionError()
        try:
            requests.get(f"http://{_address}:{port}", timeout=0.1)
            break
        except:
            time.sleep(0.05)
            max_wait_time -= 0.05

    yield f"http://{_address}:{port}"

    container.stop(timeout=1)
    while container_id in [ct.id for ct in client.containers.list(all=True)]:
        time.sleep(0.05)
    
    assert container_id not in [ct.id for ct in client.containers.list(all=True)]

@pytest.fixture
def initialized_vault_server(vault_server):
    client = hvac.Client(url=vault_server)
    result = client.sys.initialize(secret_shares=5, secret_threshold=3)
    return {
        "vault_addr": vault_server,
        "keys":result["keys"],
        "root_token":result["root_token"]
    }

@pytest.fixture
def gpg_initialized_vault_server(vault_server, five_temp_key):
    client = hvac.Client(url=vault_server)
    pgps = [ vault_init.generate_gpg_hvac_vault(k) for k in five_temp_key ]
    result = client.sys.initialize(secret_shares=5, secret_threshold=3, pgp_keys=pgps)
    return {
        "vault_addr": vault_server,
        "keys":result["keys"],
        "root_token":result["root_token"]
    }

@pytest.fixture
def root_gpg_initialized_vault_server(vault_server, single_temp_key):
    client = hvac.Client(url=vault_server)
    root_token_gpg = vault_init.generate_gpg_hvac_vault(single_temp_key)
    result = client.sys.initialize(secret_shares=5, secret_threshold=3, root_token_pgp_key=root_token_gpg)
    return {
        "vault_addr": vault_server,
        "keys":result["keys"],
        "root_token":result["root_token"]
    }

@pytest.fixture
def full_gpg_initialized_vault_server(vault_server, five_temp_key, single_temp_key):
    client = hvac.Client(url=vault_server)
    pgps = [  vault_init.generate_gpg_hvac_vault(k) for k in five_temp_key ]
    root_token_gpg = vault_init.generate_gpg_hvac_vault(single_temp_key)
    result = client.sys.initialize(secret_shares=5, secret_threshold=3, pgp_keys=pgps, root_token_pgp_key=root_token_gpg)
    return {
        "vault_addr": vault_server,
        "keys":result["keys"],
        "root_token":result["root_token"]
    }

@pytest.fixture
def sample_config():
    return {
        "key_share":5,
        "key_threshold":3,
        "can_init": True,
    }

@pytest.fixture
def sample_config_gpg(five_temp_key, single_temp_key):
    return {
        "key_share":5,
        "key_threshold":3,
        "gpgs": [ k for k in five_temp_key ],
        "root_token_gpg": single_temp_key,
        "can_init": True,
    }

@pytest.fixture
def sample_config_gpg_without_private(five_temp_key, single_temp_key):
    keys = [ k for k in five_temp_key ]
    root_key = single_temp_key
    _delete_gpg_keys()
    return {
        "key_share":5,
        "key_threshold":3,
        "gpgs": keys,
        "root_token_gpg":root_key,
        "can_init": True,
    }


@pytest.fixture
def sample_config_wrong_gpg(five_temp_wrong_key):
    return {
        "key_share":5,
        "key_threshold":3,
        "gpgs": [ k for k in five_temp_wrong_key ],
    }

def _delete_gpg_keys():
    with gpg.Context(armor=True) as gpg_context:
        for k in list(gpg_context.keylist(secret=True)):
            _k = gpg_context.get_key(k.fpr, secret = True)
            gpg_context.op_delete_ext(_k, GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE)
        assert len(list(gpg_context.keylist(secret=True))) == 0

def test_good_env_vars_full(mock_full_env_vault):
    args = vault_init.parse_args([])
    assert args["key_share"] == 2
    assert args["key_threshold"] == 1

    assert args["root_token_gpg"] == "-- ROOT PGP --"
    assert args["vault_addr"] == "http://monkeyhost:8200"
    assert "test_env_keys1" in args["keys"]
    assert "test_env_keys2" in args["keys"]

    assert "-- ENV KEYS PGP 1 --" in args["gpgs"]
    assert "-- ENV KEYS PGP 2 --" in args["gpgs"]

    assert args["can_init"]

def test_args_cli_full(full_cli_args):
    args = vault_init.parse_args(full_cli_args)
    assert args["key_share"] == 3
    assert args["key_threshold"] == 2

    assert args["root_token_gpg"] == "-- CLI ROOT PGP --"
    assert args["vault_addr"] == "http://clihost:8200"

    assert "test_cli_keys1" in args["keys"]
    assert "test_cli_keys2" in args["keys"]

    assert "-- CLI KEYS PGP 1 --" in args["gpgs"]
    assert "-- CLI KEYS PGP 2 --" in args["gpgs"]
    assert "-- CLI KEYS PGP 3 --" in args["gpgs"]

    assert args["can_init"]

def test_args_cli_full_wrong_gpg_keys(full_cli_missing_one_gpgs_args):
    with pytest.raises(ValueError):
        vault_init.parse_args(full_cli_missing_one_gpgs_args)

def test_args_env_full_wrong_gpg_keys(mock_full_env_missing_one_gpgs_vault):
    with pytest.raises(ValueError):
        vault_init.parse_args([])
    

def test_args_env_plus_cli_full(mock_full_env_vault, full_cli_args):
    args = vault_init.parse_args(full_cli_args)
    assert args["key_share"] == 3
    assert args["key_threshold"] == 2
    assert args["root_token_gpg"] == "-- CLI ROOT PGP --"
    assert args["vault_addr"] == "http://clihost:8200"

    assert "test_cli_keys1" in args["keys"]
    assert "test_cli_keys2" in args["keys"]
    assert "test_env_keys1" in args["keys"]
    assert "test_env_keys2" in args["keys"]

    assert "-- CLI KEYS PGP 1 --" in args["gpgs"]
    assert "-- CLI KEYS PGP 2 --" in args["gpgs"]
    assert "-- CLI KEYS PGP 3 --" in args["gpgs"]

    assert "-- ENV KEYS PGP 1 --" not in args["gpgs"]
    assert "-- ENV KEYS PGP 2 --" not in args["gpgs"]

    assert args["can_init"]


def test_good_env_vars_unseal(mock_unseal_env_vault):
    args = vault_init.parse_args([])
    assert args["vault_addr"] == "http://monkeyhost:8200"
    assert "test_env_keys1" in args["keys"]
    assert "test_env_keys2" in args["keys"]
    assert not args["can_init"]

def test_args_cli_unseal(unseal_cli_args):
    args = vault_init.parse_args(unseal_cli_args)
    assert args["vault_addr"] == "http://clihost:8200"
    assert "test_cli_keys1" in args["keys"]
    assert "test_cli_keys2" in args["keys"]
    assert not args["can_init"]

def test_args_env_plus_cli_unseal(mock_unseal_env_vault, unseal_cli_args):
    args = vault_init.parse_args(unseal_cli_args)
    assert args["vault_addr"] == "http://clihost:8200"
    assert "test_cli_keys1" in args["keys"]
    assert "test_cli_keys2" in args["keys"]
    assert "test_env_keys1" in args["keys"]
    assert "test_env_keys2" in args["keys"]
    assert not args["can_init"]

def test_empty_env_vars():
    with pytest.raises(ValueError):
        vault_init.parse_args([])

def test_validate_endpoint():
    assert vault_init.validate_endpoint("https://localhost:8080") is True
    with pytest.raises(ValueError):
        vault_init.validate_endpoint("https://localhost:999999")
    with pytest.raises(ValueError):
        vault_init.validate_endpoint("hxps://localhost")

def test_validate_key_count():
    assert vault_init.validate_key_count(1,1) is True
    assert vault_init.validate_key_count(2,1) is True
    assert vault_init.validate_key_count(None,None) is True
    with pytest.raises(ValueError):
        vault_init.validate_key_count(-1, 2)
    with pytest.raises(ValueError):
        vault_init.validate_key_count(2, -2)
    with pytest.raises(ValueError):
        vault_init.validate_key_count(2, 5)

def test_generate_unseal_key_set():
    keys = vault_init.generate_unseal_key_set(["0", "1", "2"])
    assert len(keys) == 3
    for i in range(0, 3):
        assert str(i) in keys

    keys = vault_init.generate_unseal_key_set([["0"], ["1"], "2"])
    assert len(keys) == 3
    for i in range(0, 3):
        assert str(i) in keys

    keys = vault_init.generate_unseal_key_set([["0"], ["1"], ["2"]])
    assert len(keys) == 3
    for i in range(0, 3):
        assert str(i) in keys

def test_generate_key(single_temp_key):
    assert vault_init.generate_gpg_hvac_vault(single_temp_key) in single_temp_key.replace(b"\n",b"").decode()

def test_generate_five_keys(five_temp_key):
    for key in five_temp_key:
        assert vault_init.generate_gpg_hvac_vault(key) in key.replace(b"\n",b"").decode()

def test_vault_server_running(vault_server):
    client = vault_init.create_client({"vault_addr":vault_server})
    assert client.sys.is_sealed()
    assert not client.sys.is_initialized()

def test_vault_init_without_gpg(vault_server, sample_config):
    sample_config["vault_addr"] = vault_server
    client = vault_init.create_client(sample_config)
    result = vault_init.init(client, sample_config)
    assert len(result["keys"]) == sample_config["key_share"]
    assert len(result["root_token"]) != 0
    assert client.sys.is_initialized()

def test_vault_unseal(initialized_vault_server):
    client = vault_init.create_client(initialized_vault_server)
    assert client.sys.is_initialized()
    vault_init.unseal(client, initialized_vault_server)
    assert not client.sys.is_sealed()
    client.token = initialized_vault_server["root_token"]
    assert client.is_authenticated()

def test_vault_unseal_bad_key(initialized_vault_server, random_hex):
    client = vault_init.create_client(initialized_vault_server)
    assert client.sys.is_initialized()
    initialized_vault_server["keys"] = [next(random_hex) for i in range(0, len(initialized_vault_server["keys"]))]
    with pytest.raises(vault_init.errors.BadKeysProvided):
        vault_init.unseal(client, initialized_vault_server)
    assert client.sys.is_sealed()
    client.token = next(random_hex)
    with pytest.raises(hvac.exceptions.VaultDown):
        assert not client.is_authenticated()

def test_vault_unseal_bad_token(initialized_vault_server, random_hex):
    client = vault_init.create_client(initialized_vault_server)
    assert client.sys.is_initialized()
    vault_init.unseal(client, initialized_vault_server)
    assert not client.sys.is_sealed()
    client.token = next(random_hex)
    assert not client.is_authenticated()

def test_vault_unseal_not_enough_keys(initialized_vault_server, random_hex):
    client = vault_init.create_client(initialized_vault_server)
    assert client.sys.is_initialized()
    initialized_vault_server["keys"] = initialized_vault_server["keys"][0:1]
    with pytest.raises(vault_init.NotEnoughtKeysError):
        vault_init.unseal(client, initialized_vault_server)
    assert client.sys.is_sealed()

def test_vault_init_with_wrong_gpg(vault_server, sample_config_wrong_gpg):
    sample_config_wrong_gpg["vault_addr"] = vault_server
    client = vault_init.create_client(sample_config_wrong_gpg)
    with pytest.raises(vault_init.BadInitParameterValue):
        vault_init.init(client, sample_config_wrong_gpg)
    assert not client.sys.is_initialized()

def test_vault_init_with_gpg(vault_server, sample_config_gpg):
    sample_config_gpg["vault_addr"] = vault_server
    client = vault_init.create_client(sample_config_gpg)
    result = vault_init.init(client, sample_config_gpg)
    assert len(result["keys"]) == sample_config_gpg["key_share"]
    assert len(result["root_token"]) != 0
    assert client.sys.is_initialized()

def test_vault_cannot_unseal_with_gpg(gpg_initialized_vault_server):
    client = vault_init.create_client(gpg_initialized_vault_server)
    _delete_gpg_keys()

    assert client.sys.is_initialized()
    with pytest.raises(vault_init.BadKeysProvided):
        vault_init.unseal(client, gpg_initialized_vault_server)
    assert client.sys.is_sealed()
    client.token = gpg_initialized_vault_server["root_token"]
    with pytest.raises(hvac.exceptions.VaultDown):
        assert not client.is_authenticated()

def test_vault_can_unseal_with_gpg(gpg_initialized_vault_server):
    client = vault_init.create_client(gpg_initialized_vault_server)

    assert client.sys.is_initialized()
    vault_init.unseal(client, gpg_initialized_vault_server)
    assert not client.sys.is_sealed()
    client.token = gpg_initialized_vault_server["root_token"]
    assert client.is_authenticated()

def test_vault_cannot_authenticated_with_gpg(root_gpg_initialized_vault_server):
    client = vault_init.create_client(root_gpg_initialized_vault_server)
    _delete_gpg_keys()

    assert client.sys.is_initialized()
    vault_init.unseal(client, root_gpg_initialized_vault_server)
    assert not client.sys.is_sealed()
    root_token_decrypt = vault_init.try_decrypt_gpg_key(root_gpg_initialized_vault_server["root_token"])
    assert root_token_decrypt is None

def test_vault_can_authenticated_with_gpg(root_gpg_initialized_vault_server):
    client = vault_init.create_client(root_gpg_initialized_vault_server)

    assert client.sys.is_initialized()
    vault_init.unseal(client, root_gpg_initialized_vault_server)
    assert not client.sys.is_sealed()
    root_token_decrypt = vault_init.try_decrypt_gpg_key(root_gpg_initialized_vault_server["root_token"])
    assert root_token_decrypt is not None
    client.token = root_token_decrypt
    assert client.is_authenticated()

def test_full_vault_cannot_authenticated_with_gpg(full_gpg_initialized_vault_server):
    client = vault_init.create_client(full_gpg_initialized_vault_server)
    _delete_gpg_keys()

    assert client.sys.is_initialized()
    with pytest.raises(vault_init.BadKeysProvided):
        vault_init.unseal(client, full_gpg_initialized_vault_server)
    assert client.sys.is_sealed()
    root_token_decrypt = vault_init.try_decrypt_gpg_key(full_gpg_initialized_vault_server["root_token"])
    assert root_token_decrypt is None
    client.token = root_token_decrypt

def test_full_vault_can_authenticated_with_gpg(full_gpg_initialized_vault_server):
    client = vault_init.create_client(full_gpg_initialized_vault_server)

    assert client.sys.is_initialized()
    vault_init.unseal(client, full_gpg_initialized_vault_server)
    assert not client.sys.is_sealed()
    root_token_decrypt = vault_init.try_decrypt_gpg_key(full_gpg_initialized_vault_server["root_token"])
    assert root_token_decrypt is not None
    client.token = root_token_decrypt
    assert client.is_authenticated()


def test_can_unseal_true():
    assert vault_init.can_unseal({"keys":["1", "2"]}, [])

def test_can_unseal_false():
    assert not vault_init.can_unseal({}, [])

def test_gpg_can_decrypt_true(five_temp_key):
    assert vault_init.can_unseal({"gpgs":five_temp_key}, ["fake"])

def test_gpg_can_decrypt_false(five_temp_key):
    _delete_gpg_keys()
    assert not vault_init.can_unseal({"gpgs":five_temp_key}, ["fake"])

def test_cannot_init_twice(vault_server, sample_config):
    sample_config["vault_addr"] = vault_server
    client = vault_init.create_client(sample_config)
    vault_init.init(client, sample_config)
    assert client.sys.is_initialized()
    with pytest.raises(vault_init.BadInitParameterValue):
        vault_init.init(client, sample_config)

def test_cannot_unseal_twice(vault_server, sample_config):
    sample_config["vault_addr"] = vault_server
    client = vault_init.create_client(sample_config)
    init_result = vault_init.init(client, sample_config)
    vault_init.unseal(client, sample_config, init_result)
    assert client.sys.is_initialized()
    assert not client.sys.is_sealed()
    assert vault_init.unseal(client, sample_config, init_result) == 0

def test_full_no_gpg(vault_server, sample_config):
    sample_config["vault_addr"] = vault_server
    result, result_dir = vault_init.process_vault(sample_config)
    root_token = result_dir["init_result"]["root_token"]
    assert result
    assert result_dir["init_result"]["is_init"]
    assert result_dir["init_result"]["init_performed"]
    assert len(result_dir["init_result"]["keys"]) == sample_config["key_share"]
    assert not result_dir["init_result"]["keys_gpg_encrypted"]
    assert not result_dir["init_result"]["root_token_gpg_encrypted"]

    assert result_dir["unseal_result"]["is_unseal"]
    assert result_dir["unseal_result"]["unseal_performed"]
    assert result_dir["unseal_result"]["keys_used_count"] == sample_config["key_threshold"]

    client = vault_init.create_client(sample_config)
    assert client.sys.is_initialized()
    assert not client.sys.is_sealed()
    client.token = root_token
    assert client.is_authenticated()

def test_full_no_gpg_with_reseal(vault_server, sample_config):
    sample_config["vault_addr"] = vault_server
    result, result_dir = vault_init.process_vault(sample_config)
    root_token = result_dir["init_result"]["root_token"]
    assert result
    assert result_dir["init_result"]["is_init"]
    assert result_dir["init_result"]["init_performed"]
    assert len(result_dir["init_result"]["keys"]) == sample_config["key_share"]
    assert not result_dir["init_result"]["keys_gpg_encrypted"]
    assert not result_dir["init_result"]["root_token_gpg_encrypted"]

    assert result_dir["unseal_result"]["is_unseal"]
    assert result_dir["unseal_result"]["unseal_performed"]
    assert result_dir["unseal_result"]["keys_used_count"] == sample_config["key_threshold"]

    client = vault_init.create_client(sample_config)
    assert client.sys.is_initialized()
    assert not client.sys.is_sealed()
    client.token = root_token
    assert client.is_authenticated()

    client.sys.seal()
    assert client.sys.is_sealed()
    vault_init.unseal(client, sample_config, result_dir["init_result"])
    assert not client.sys.is_sealed()
    assert client.is_authenticated()

def test_full_gpg(vault_server, sample_config_gpg):
    sample_config_gpg["vault_addr"] = vault_server
    result, result_dir = vault_init.process_vault(sample_config_gpg)
    root_token = vault_init.try_decrypt_gpg_key(result_dir["init_result"]["root_token"])
    assert result
    assert result_dir["init_result"]["is_init"]
    assert result_dir["init_result"]["init_performed"]
    assert len(result_dir["init_result"]["keys"]) == sample_config_gpg["key_share"]
    assert result_dir["init_result"]["root_token"] is not None
    assert result_dir["init_result"]["keys_gpg_encrypted"]
    assert result_dir["init_result"]["root_token_gpg_encrypted"]

    assert result_dir["unseal_result"]["is_unseal"]
    assert result_dir["unseal_result"]["unseal_performed"]
    assert result_dir["unseal_result"]["keys_used_count"] == sample_config_gpg["key_threshold"]

    client = vault_init.create_client(sample_config_gpg)
    assert client.sys.is_initialized()
    assert not client.sys.is_sealed()
    client.token = root_token
    assert client.is_authenticated()

def test_full_gpg_with_reseal(vault_server, sample_config_gpg):
    sample_config_gpg["vault_addr"] = vault_server
    result, result_dir = vault_init.process_vault(sample_config_gpg)
    root_token = vault_init.try_decrypt_gpg_key(result_dir["init_result"]["root_token"])
    assert result
    assert result_dir["init_result"]["is_init"]
    assert result_dir["init_result"]["init_performed"]
    assert len(result_dir["init_result"]["keys"]) == sample_config_gpg["key_share"]
    assert result_dir["init_result"]["root_token"] is not None
    assert result_dir["init_result"]["keys_gpg_encrypted"]
    assert result_dir["init_result"]["root_token_gpg_encrypted"]

    assert result_dir["unseal_result"]["is_unseal"]
    assert result_dir["unseal_result"]["unseal_performed"]
    assert result_dir["unseal_result"]["keys_used_count"] == sample_config_gpg["key_threshold"]

    client = vault_init.create_client(sample_config_gpg)
    assert client.sys.is_initialized()
    assert not client.sys.is_sealed()
    client.token = root_token
    assert client.is_authenticated()

    client.sys.seal()
    assert client.sys.is_sealed()
    vault_init.unseal(client, sample_config_gpg, result_dir["init_result"])
    assert not client.sys.is_sealed()
    assert client.is_authenticated()

def test_full_gpg_no_private(vault_server, sample_config_gpg_without_private):
    sample_config_gpg_without_private["vault_addr"] = vault_server
    result, result_dir = vault_init.process_vault(sample_config_gpg_without_private)

    assert result
    assert result_dir["init_result"]["is_init"]
    assert result_dir["init_result"]["init_performed"]
    assert len(result_dir["init_result"]["keys"]) == sample_config_gpg_without_private["key_share"]
    assert result_dir["init_result"]["keys_gpg_encrypted"]
    assert result_dir["init_result"]["root_token_gpg_encrypted"]
    assert result_dir["init_result"]["root_token"] is not None
    assert vault_init.try_decrypt_gpg_key(result_dir["init_result"]["root_token"]) is None

    assert not result_dir["unseal_result"]["is_unseal"]
    assert not result_dir["unseal_result"]["unseal_performed"]

    client = vault_init.create_client(sample_config_gpg_without_private)
    assert client.sys.is_initialized()
    assert client.sys.is_sealed()
