# -*- coding: utf-8 -*-

# This source file is part of mc4p,
# the Minecraft Portable Protocol-Parsing Proxy.

# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://www.wtfpl.net/txt/copying/ for more details

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_v1_5


def decode_public_key(bytes):
    """Decodes a public RSA key in ASN.1 format as defined by x.509"""
    return RSA.importKey(bytes)


def encode_public_key(key):
    """Encodes a public RSA key in ASN.1 format as defined by x.509"""
    return key.publickey().exportKey(format="DER")


def generate_key_pair():
    """Generates a 1024 bit RSA key pair"""
    return RSA.generate(1024)


def generate_random_bytes(length):
    return Random.get_random_bytes(length)


def generate_challenge_token():
    """Generates 4 random bytes"""
    return generate_random_bytes(4)


def generate_shared_secret():
    """Generates a 128 bit secret key to be used in symmetric encryption"""
    return generate_random_bytes(16)


def encrypt_shared_secret(shared_secret, public_key):
    """Encrypts the PKCS#1 padded shared secret using the public RSA key"""
    cipher = PKCS1_v1_5.new(public_key)
    return cipher.encrypt(shared_secret)


def decrypt_shared_secret(encrypted_key, private_key):
    """Decrypts the PKCS#1 padded shared secret using the private RSA key"""
    cipher = PKCS1_v1_5.new(private_key)
    return cipher.decrypt(encrypted_key, generate_shared_secret())


def AES128CFB8(shared_secret):
    """Creates a AES128 stream cipher using cfb8 mode"""
    return AES.new(shared_secret, AES.MODE_CFB, shared_secret)


if __name__ == "__main__":
    pair = generate_key_pair()
    nonce = generate_challenge_token()
    encrypted = encrypt_shared_secret(nonce, pair)
    decrypted = decrypt_shared_secret(encrypted, pair)
    print nonce
    print decrypted
