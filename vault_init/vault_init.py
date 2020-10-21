import sys
import argparse
import os
import urllib.parse
import gpg
import hvac
import base64
import binascii
import json
from vault_init.errors import BadInitParameterValue, NotEnoughtKeysError, BadKeysProvided


def validate_endpoint(value):
    if value is None:
        raise ValueError("vault_addr cannot be empty")
    try:
        urllib.parse.urlparse(value)
        if urllib.parse.urlparse(value).scheme.lower() not in ["http", "https"]:
            raise ValueError("Bad HTTP scheme")
        urllib.parse.urlparse(value).port
    except ValueError as expt:
        raise ValueError(f"vault_addr ({value}) is not a valid endpoint - Error was {expt}")
    return True

def validate_key_count(key_share, key_threshold):
    if key_share is None and key_threshold is None:
        return True
    if key_share < 1 or key_threshold < 1:
        raise ValueError(f"Keys count args cannot be 0 or less, key_share={key_share}, key_threshold={key_threshold}")
    if key_share < key_threshold:
        raise ValueError(f"keys_threshold cannot be greater than key_share, key_share={key_share}, key_threshold={key_threshold}")
    return True

def generate_unseal_key_set(key_list):
    keys = []
    if len(key_list) > 0:
        keys = list(set([ k[0] for k in key_list ])) if isinstance(key_list[0], list) else key_list
    keys += [v for k,v in os.environ.items() if k.startswith("VAULT_UNSEALKEY_")]
    return list(set(keys))

def generate_gpg_keys_list(key_list):
    if len(key_list) == 0:
        return list(set([v for k,v in os.environ.items() if k.startswith("VAULT_KEYS_GPG_")]))
    return list(set([ k[0] for k in key_list ])) if isinstance(key_list[0], list) else key_list

def generate_gpg_hvac_vault(gpg_value):
    with gpg.Context(armor=False) as c, gpg.Data() as expkey:
        c.op_import(gpg_value)
        import_result =  c.op_import_result()
        if import_result:
            c.op_export(import_result.imports[0].fpr, 0, expkey)
            expkey.seek(0, os.SEEK_SET)
            return base64.b64encode(expkey.read()).decode()
        else:
            return base64.b64encode(b'').decode()

def try_decrypt_gpg_key(value):
    # If provided value is a hex representation of data
    # First convert it to bin then base64encode it
    try:
        binary_string = binascii.unhexlify(value)
        with gpg.Context(armor=True) as c:
            plain, _, _ = c.decrypt(binary_string)
            return plain.decode()
    except:
        try:
            binary_string = base64.b64decode(value)
            with gpg.Context(armor=True) as c:
                plain, _, _ = c.decrypt(binary_string)
                return plain.decode()
        except:
            return None

def can_unseal(args, init_keys):
    # If keys provided and not gpg
    if len(args.get("gpgs", [])) == 0 and len(args.get("keys",[])) > 0:
        return True
    # If keys not provided but init and no gpg
    if len(args.get("gpgs", [])) == 0 and len(init_keys) > 0:
        return True
    # If gpg keys provided and init
    return_value = len(init_keys) > 0
    for k in args.get("gpgs", []):
        if isinstance(k, str):
            k = k.encode()
        with gpg.Context(armor=False) as c:
            c.op_import(gpg.Data(k))
            import_result =  c.op_import_result()
            if not import_result:
                return False
            key_id = c.get_key(import_result.imports[0].fpr)
            try:
                ciphertext, _, _ = c.encrypt(b"_", always_trust=True, sign=False, recipients=[key_id])
                plaintext, _, _ = c.decrypt(ciphertext)
                return_value &= plaintext == b"_"
            except gpg.errors.GPGMEError:
                return False
    return return_value

def parse_args(args):
    parser = argparse.ArgumentParser(description="""Vault Inititalizer and AutoUnsealer, args can be provided by CLI and/or ENV var. if both specified, cli args will be preferred (specially GPG keys)""")
    parser.add_argument('--vault_addr', default=os.environ.get('VAULT_ADDR'), metavar="VAULT_ADDR")
    parser.add_argument('--key_share', type=int, default=os.environ.get('VAULT_KEY_SHARE'), metavar="VAULT_KEY_SHARE")
    parser.add_argument('--key_threshold', type=int, default=os.environ.get('VAULT_KEY_THRESHOLD'), metavar="VAULT_KEY_THRESHOLD")
    parser.add_argument('--root_token_gpg', default=os.environ.get('VAULT_ROOT_TOKEN_GPG'), metavar="VAULT_ROOT_TOKEN_GPG")

    parser.add_argument('--gpgs',  nargs='+', action='append', metavar="VAULT_KEYS_GPG_#", default=[])
    parser.add_argument('--keys', nargs='+', action='append', metavar="VAULT_UNSEALKEY_#", default=[])
    parse_args = parser.parse_args(args)

    validate_endpoint(parse_args.vault_addr)
    validate_key_count(parse_args.key_share, parse_args.key_threshold)

    parse_args.gpgs = generate_gpg_keys_list(parse_args.gpgs)
    parse_args.keys = generate_unseal_key_set(parse_args.keys)

    if len(parse_args.gpgs) > 0 and len(parse_args.gpgs) != parse_args.key_share:
        raise ValueError("The number of gpgs keys must match the count of key_share, gpgs_count=%d, key_share=%d" % (len(parse_args.gpgs), parse_args.key_share))

    parse_args.can_init = parse_args.key_share is not None and parse_args.key_threshold is not None

    return vars(parse_args)

def create_client(args):
    return hvac.Client(url=args["vault_addr"])

def init(client, args):
    init_args = {
        "secret_shares":args["key_share"],
        "secret_threshold": args["key_threshold"],
        "pgp_keys": [],
        "root_token_pgp_key": args.get("root_token_gpg"),
    }
    if init_args["root_token_pgp_key"]:
        init_args["root_token_pgp_key"] = generate_gpg_hvac_vault(init_args["root_token_pgp_key"])

    for k in args.get("gpgs",[]):
        init_args["pgp_keys"].append(generate_gpg_hvac_vault(k))
    init_args["pgp_keys"] = None if len(init_args["pgp_keys"]) == 0 else init_args["pgp_keys"]
    try:
        result = client.sys.initialize(**init_args)
        return {"keys": result["keys"], "root_token": result["root_token"]}
    except hvac.exceptions.InvalidRequest as e:
        raise BadInitParameterValue(str(e))

def unseal(client, args, init={}):
    arg_key = args.get("keys", [])
    init_key = init.get("keys",[])
    gpg_keys = [ k for k in[ try_decrypt_gpg_key(k) for k in arg_key + init_key ] if k is not None ]
    keys_iterator = iter(gpg_keys if len(gpg_keys) else arg_key + init_key)
    key_used_count = 0
    mandatory = -1
    try:
        while client.sys.is_sealed():
            key = next(keys_iterator)
            r = client.sys.submit_unseal_key(key)
            key_used_count += 1
            mandatory = r["t"]

    except StopIteration:
        raise NotEnoughtKeysError(mandatory_count=mandatory, used_count=key_used_count)
    except (hvac.exceptions.InternalServerError, hvac.exceptions.InvalidRequest):
        raise BadKeysProvided()
    return key_used_count

def process_vault(args):
    client = create_client(args)
    init_result = {}
    return_dict = {
        "init_result": {
            "is_init": client.sys.is_initialized(),
            "init_performed" : False
        },
        "unseal_result": {
            "is_unseal": not client.sys.is_sealed(),
            "unseal_performed" : False
        }
    }
    if not client.sys.is_initialized() and args["can_init"]:
        init_result = init(client, args)
        return_dict["init_result"] = {
            "is_init": client.sys.is_initialized(),
            "init_performed" : True,
            "keys" : init_result["keys"],
            "root_token" : init_result["root_token"],
            "keys_gpg_encrypted" : len(args.get("gpgs",[])) > 0,
            "root_token_gpg_encrypted" : args.get("root_token_gpg") is not None
        }
    if client.sys.is_sealed():
        if can_unseal(args, init_result.get("keys",[])):
            unseal_result = unseal(client, args, init_result)
            return_dict["unseal_result"] = {
                "unseal_performed" : True,
                "is_unseal": not client.sys.is_sealed(),
                "keys_used_count" : unseal_result
            }
    return True, return_dict

def main():
    args = parse_args(sys.argv[1:])
    try:
        _, return_dict = process_vault(args)
        print(json.dumps(return_dict))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"result": False, "exception": f"{e}"}))
        sys.exit(1)



