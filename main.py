#!/usr/bin/python
# coding=utf-8

import os
import binascii
from mikro import mikro_softwareid_decode
from mikro import mikro_kcdsa_sign
from mikro import mikro_base64_encode
from mikro import mikro_encode
from patch import patch_npk_file
from patch import patch_netinstall


def hex2b64(h):
    return binascii.b2a_base64(binascii.a2b_hex(h), newline=False).decode("utf8")


def generate_license(software_id, private_key: bytes, version: int = 7, level: int = 6):
    MIKRO_LICENSE_HEADER = '-----BEGIN MIKROTIK SOFTWARE KEY------------'
    MIKRO_LICENSE_FOOTER = '-----END MIKROTIK SOFTWARE KEY--------------'
    software_id = mikro_softwareid_decode(software_id)
    lic = software_id.to_bytes(6, 'little')
    lic += version.to_bytes(1, 'little')
    lic += level.to_bytes(1, 'little')
    lic += b'\0' * 8
    sig = mikro_kcdsa_sign(lic, private_key)
    lic = mikro_base64_encode(mikro_encode(lic) + sig, True)
    return MIKRO_LICENSE_HEADER + '\n' + lic[:len(lic) // 2] + '\n' + lic[len(lic) // 2:] + '\n' + MIKRO_LICENSE_FOOTER


if __name__ == '__main__':

    os.environ['MIKRO_LICENSE_PUBLIC_KEY'] = "8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"
    os.environ['MIKRO_NPK_SIGN_PUBLIC_KEY'] = "C293CED638A2A33C681FC8DE98EE26C54EADC5390C2DFCE197D35C83C416CF59"
    os.environ['MIKRO_NPK_SIGN_PUBLIC_LKEY'] = os.environ['MIKRO_NPK_SIGN_PUBLIC_KEY']  # L?
    os.environ['CUSTOM_LICENSE_PUBLIC_KEY'] = 'fb4e68dd9c46ae5c5c0b351eed5c3f8f1471157d680c75d9b7f17318d542d320'
    os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'] = '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29'
    os.environ['CUSTOM_NPK_SIGN_PUBLIC_LKEY'] = os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY']  # L?
    os.environ['CUSTOM_LICENSE_PRIVATE_KEY'] = '0200000000000000000000000000000000000000000000000000000000000000'
    os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'] = '0000000000000000000000000000000000000000000000000000000000000000'
    os.environ['MIKRO_LICENCE_URL'] = "licence.mikrotik.com"
    os.environ['CUSTOM_LICENCE_URL'] = "licence.tinytech.org"
    os.environ['MIKRO_UPGRADE_URL'] = "upgrade.mikrotik.com"
    os.environ['CUSTOM_UPGRADE_URL'] = "upgrade.tinytech.org"
    os.environ['MIKRO_CLOUD_URL'] = "cloud2.mikrotik.com"
    os.environ['CUSTOM_CLOUD_URL'] = "cloud2.tinytech.org"
    os.environ['MIKRO_CLOUD_PUBLIC_KEY'] = hex2b64("a30b9719d5d1b8d3b45846a785772ce8b7aba3e0abc3c921dc44963438b603f2")
    os.environ['CUSTOM_CLOUD_PUBLIC_KEY'] = hex2b64('3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29')

    for k, v in os.environ.items():
        if "_KEY" in k:
            print(k, len(v), repr(v))

    l = generate_license("9999-9999", bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY']), 7, 6)
    print(l)
    with open("9999-9999.key", "w") as f:
        f.write(l)

    key_replace_dict = {
        bytes.fromhex(os.environ['MIKRO_LICENSE_PUBLIC_KEY']): bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY']),
        bytes.fromhex(os.environ['MIKRO_NPK_SIGN_PUBLIC_KEY']): bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    }

    patch_npk_file(key_replace_dict,
                   bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY']),
                   bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY']),
                   r"routeros-7.12.1-arm.npk",
                   r"routeros-7.12.1-arm-patch.npk"
                   )
    patch_netinstall(key_replace_dict,
                     r"netinstall.exe",
                     "netinstall-patch.exe"
                     )
